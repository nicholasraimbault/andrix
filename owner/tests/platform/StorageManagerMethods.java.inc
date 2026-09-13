/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// SPDX-License-Identifier: Apache-2.0
// Exact candidate methods, verified by android_lifecycle.targets; not a parallel implementation.
    private void connectVold() {
        synchronized (mVoldConnectionLock) {
            if (mConnectingVold) return;
            if (mVold != null) {
                if (mVold.asBinder().isBinderAlive()) return;
                mCeAccess.died(mVold.asBinder());
                mVold = null;
            }
            mConnectingVold = true;
        }
        IVold connected = null;
        try {
            final IBinder binder = ServiceManager.getService("vold");
            final DeathRecipient death = new DeathRecipient() {
                @Override public void binderDied() {
                    synchronized (mVoldConnectionLock) {
                        // A delayed old callback must not clear a replacement binder.
                        if (mVold == null || mVold.asBinder() != binder) return;
                        Slog.w(TAG, "vold died; reconnecting");
                        mVold = null;
                        mCeAccess.died(binder);
                    }
                    connectVold();
                }
            };
            boolean linked = false;
            try {
                if (binder != null) {
                    binder.linkToDeath(death, 0);
                    linked = true;
                    final IVold candidate = IVold.Stub.asInterface(binder);
                    candidate.setListener(mListener); // No storage/connection lock held.
                    synchronized (mVoldConnectionLock) {
                        // Covers death delivered before the candidate was published.
                        if (binder.isBinderAlive()) {
                            // Key methods read mVold without this connection lock.
                            // Install observation identity BEFORE exposing the binder,
                            // or a revocation could start against an untracked backend.
                            mCeAccess.connected(binder);
                            // Local observation callbacks can race death. Do not
                            // publish a candidate which died during that handoff.
                            if (binder.isBinderAlive()) {
                                mVold = candidate;
                                connected = candidate;
                            } else {
                                mCeAccess.died(binder);
                            }
                        }
                    }
                } else {
                    Slog.w(TAG, "vold not found; trying again");
                }
            } catch (RemoteException e) {
                Slog.w(TAG, "vold listener rejected; trying again", e);
            } finally {
                if (linked && connected == null) binder.unlinkToDeath(death, 0);
            }
        } finally {
            synchronized (mVoldConnectionLock) { mConnectingVold = false; }
        }
        final IVold current;
        synchronized (mVoldConnectionLock) { current = mVold; }
        if (current == null) {
            // Death may have run after publication while mConnectingVold was
            // still true. That callback could not reconnect; this path must.
            BackgroundThread.getHandler().postDelayed(() -> {
                connectVold();
            }, DateUtils.SECOND_IN_MILLIS);
        } else if (current == connected) {
            restoreCeUnlockedUsers(connected);
            synchronized (mVoldConnectionLock) {
                if (mVold != connected) return;
            }
            onDaemonConnected();
        }
    }

    private void restoreCeUnlockedUsers(IVold vold) {
        final CeStorageAccessTracker.Operation observation =
                mCeAccess.beginRestore(voldIdentity(vold));
        int[] userIds = EmptyArray.INT;
        boolean success = false;
        try {
            userIds = vold.getUnlockedUsers();
            if (!ArrayUtils.isEmpty(userIds)) {
                Slog.d(TAG, "CE storage for users " + Arrays.toString(userIds)
                        + " is already unlocked");
                synchronized (mLock) {
                    // Preserve append semantics: restarted vold can know fewer
                    // unlocked users than system_server. Do not clear this cache.
                    mCeUnlockedUsers.appendAll(userIds);
                }
            }
            success = true;
        } catch (Exception e) {
            Slog.e(TAG, "Failed to get unlocked users from vold", e);
        } finally {
            mCeAccess.completeBulk(observation, success,
                    userIds == null ? EmptyArray.INT : userIds);
        }
    }

    public void lockCeStorage(int userId) {
        super.lockCeStorage_enforcePermission();
        if (userId == UserHandle.USER_SYSTEM && UserManager.isHeadlessSystemUserMode()) {
            throw new IllegalArgumentException("Headless system user data cannot be locked..");
        }
        final IVold vold = mVold;
        final CeStorageAccessTracker.Operation observation =
                mCeAccess.beginRevocation(userId, voldIdentity(vold));
        boolean success = false;
        try {
            if (!isCeStorageUnlocked(userId)) {
                Slog.d(TAG, "User " + userId + "'s CE storage is already locked");
                success = true;
                return;
            }
            vold.lockCeStorage(userId);
            synchronized (mLock) { mCeUnlockedUsers.remove(userId); }
            success = true;
        } catch (Exception e) {
            Slog.wtf(TAG, e);
        } finally {
            mCeAccess.complete(observation, success);
        }
    }

    private void resetIfBootedAndConnected() {
        Slog.d(TAG, "Thinking about reset, mBootCompleted=" + mBootCompleted
                + ", mDaemonConnected=" + mDaemonConnected);
        if (mBootCompleted && mDaemonConnected) {
            final IVold vold = mVold;
            final CeStorageAccessTracker.Operation observation =
                    mCeAccess.beginReset(voldIdentity(vold));
            boolean observedSuccess = false;
            try {
                final UserManager userManager = mContext.getSystemService(UserManager.class);
                final List<UserInfo> users = userManager.getUsers();

                extendWatchdogTimeout("#onReset might be slow");
                mStorageSessionController.onReset(vold, () -> {
                    mHandler.removeCallbacksAndMessages(null);
                });

                final int[] systemUnlockedUsers;
                synchronized (mLock) {
                    // make copy as sorting can change order
                    systemUnlockedUsers = Arrays.copyOf(mSystemUnlockedUsers,
                            mSystemUnlockedUsers.length);

                    mDisks.clear();
                    mVolumes.clear();

                    addInternalVolumeLocked();
                }

                try {
                    // Reset vold to tear down existing disks/volumes and start from
                    // a clean state.  Exception: already-unlocked user storage will
                    // remain unlocked and is not affected by the reset.
                    //
                    // TODO(b/135341433): Remove cautious logging when FUSE is stable
                    Slog.i(TAG, "Resetting vold...");
                    vold.reset();
                    Slog.i(TAG, "Reset vold");

                    // Tell vold about all existing and started users
                    for (UserInfo user : users) {
                        if (user.isCloneProfile()) {
                            vold.onUserAdded(user.id, user.serialNumber, user.profileGroupId);
                        } else {
                            vold.onUserAdded(user.id, user.serialNumber, -1);
                        }
                    }
                    for (int userId : systemUnlockedUsers) {
                        vold.onUserStarted(userId);
                        mStoraged.onUserStarted(userId);
                    }
                    restoreSystemUnlockedUsers(vold, userManager, users, systemUnlockedUsers);
                    vold.onSecureKeyguardStateChanged(mSecureKeyguardShowing);
                    mStorageManagerInternal.onReset(vold);
                    observedSuccess = true;
                } catch (Exception e) {
                    Slog.wtf(TAG, e);
                }
            } finally {
                final int[] unlocked;
                synchronized (mLock) { unlocked = mCeUnlockedUsers.all().clone(); }
                mCeAccess.completeBulk(observation, observedSuccess, unlocked);
            }
        }
    }

    private void restoreSystemUnlockedUsers(IVold vold, UserManager userManager, List<UserInfo> allUsers,
            int[] systemUnlockedUsers) throws Exception {
        Arrays.sort(systemUnlockedUsers);
        UserManager.invalidateIsUserUnlockedCache();
        for (UserInfo user : allUsers) {
            int userId = user.id;
            if (!userManager.isUserRunning(userId)) {
                continue;
            }
            if (Arrays.binarySearch(systemUnlockedUsers, userId) >= 0) {
                continue;
            }
            boolean unlockingOrUnlocked = userManager.isUserUnlockingOrUnlocked(userId);
            if (!unlockingOrUnlocked) {
                continue;
            }
            Slog.w(TAG, "UNLOCK_USER lost from vold reset, will retry, user:" + userId);
            vold.onUserStarted(userId);
            mStoraged.onUserStarted(userId);
            mHandler.obtainMessage(H_COMPLETE_UNLOCK_USER, userId, /* arg2 (unusued) */ 0)
                    .sendToTarget();
        }
    }

        public void unlockCeStorage(@UserIdInt int userId, byte[] secret) {
            final IVold vold = mVold;
            final CeStorageAccessTracker.Operation observation =
                    mCeAccess.beginAvailable(userId, voldIdentity(vold));
            boolean success = false;
            try {
                if (StorageManager.isFileEncrypted()) {
                    try {
                        vold.unlockCeStorage(userId, secret);
                    } catch (RemoteException e) {
                        e.rethrowAsRuntimeException();
                    }
                }
                synchronized (mLock) { mCeUnlockedUsers.append(userId); }
                success = true;
            } finally {
                mCeAccess.complete(observation, success);
            }
        }
