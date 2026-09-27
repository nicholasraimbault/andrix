/*
 * Copyright (C) 2014 The Android Open Source Project
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

// Exact fragments; checked by tests/installer-durability/pis_reverse_write_sync.py.
    @Override
    public void write(String name, long offsetBytes, long lengthBytes,
            ParcelFileDescriptor fd) {
        assertCanWrite(fd != null);
        try {
            doWriteInternal(name, offsetBytes, lengthBytes, fd);
        } catch (IOException e) {
            throw ExceptionUtils.wrap(e);
        }
    }

    @Override
    public void stageViaHardLink(String path) {
        final int callingUid = Binder.getCallingUid();
        if (callingUid != Process.SYSTEM_UID) {
            throw new SecurityException("link() can only be run by the system");
        }

        final File target = new File(path);
        final File source = new File(stageDir, target.getName());
        var sourcePath = source.getAbsolutePath();
        try {
            try {
                Os.link(path, sourcePath);
                // Grant READ access for APK to be read successfully
                Os.chmod(sourcePath, DEFAULT_FILE_ACCESS_MODE);
            } catch (ErrnoException e) {
                e.rethrowAsIOException();
            }
            if (!SELinux.restorecon(source)) {
                throw new IOException("Can't relabel file: " + source);
            }
        } catch (IOException e) {
            try {
                Os.unlink(sourcePath);
            } catch (Exception ignored) {
                Slog.d(TAG, "Failed to unlink session file: " + sourcePath);
            }

            throw ExceptionUtils.wrap(e);
        }
    }

    private ParcelFileDescriptor openTargetInternal(String path, int flags, int mode)
            throws IOException, ErrnoException {
        // TODO: this should delegate to DCS so the system process avoids
        // holding open FDs into containers.
        final FileDescriptor fd = Os.open(path, flags, mode);
        return new ParcelFileDescriptor(fd);
    }

    private ParcelFileDescriptor createRevocableFdInternal(RevocableFileDescriptor fd,
            ParcelFileDescriptor pfd) throws IOException {
        int releasedFdInt = pfd.detachFd();
        FileDescriptor releasedFd = new FileDescriptor();
        releasedFd.setInt$(releasedFdInt);
        fd.init(mContext, releasedFd);
        return fd.getRevocableFileDescriptor();
    }

    private ParcelFileDescriptor doWriteInternal(String name, long offsetBytes, long lengthBytes,
            ParcelFileDescriptor incomingFd) throws IOException {
        // Quick validity check of state, and allocate a pipe for ourselves. We
        // then do heavy disk allocation outside the lock, but this open pipe
        // will block any attempted install transitions.
        final RevocableFileDescriptor fd;
        final FileBridge bridge;
        synchronized (mLock) {
            if (PackageInstaller.ENABLE_REVOCABLE_FD) {
                fd = new RevocableFileDescriptor();
                bridge = null;
                mFds.add(fd);
            } else {
                fd = null;
                bridge = new FileBridge();
                mBridges.add(bridge);
            }
        }

        try {
            // Use installer provided name for now; we always rename later
            if (!FileUtils.isValidExtFilename(name)) {
                throw new IllegalArgumentException("Invalid name: " + name);
            }
            final File target;
            final long identity = Binder.clearCallingIdentity();
            try {
                target = new File(stageDir, name);
            } finally {
                Binder.restoreCallingIdentity(identity);
            }

            // If file is app metadata then set permission to 0640 to deny user read access since it
            // might contain sensitive information.
            int mode = name.equals(APP_METADATA_FILE_NAME)
                    ? APP_METADATA_FILE_ACCESS_MODE : DEFAULT_FILE_ACCESS_MODE;
            ParcelFileDescriptor targetPfd = openTargetInternal(target.getAbsolutePath(),
                    O_CREAT | O_WRONLY, mode);
            Os.chmod(target.getAbsolutePath(), mode);

            // If caller specified a total length, allocate it for them. Free up
            // cache space to grow, if needed.
            if (stageDir != null && lengthBytes > 0) {
                mContext.getSystemService(StorageManager.class).allocateBytes(
                        targetPfd.getFileDescriptor(), lengthBytes,
                        InstallLocationUtils.translateAllocateFlags(params.installFlags));
            }

            if (offsetBytes > 0) {
                Os.lseek(targetPfd.getFileDescriptor(), offsetBytes, OsConstants.SEEK_SET);
            }

            if (incomingFd != null) {
                // In "reverse" mode, we're streaming data ourselves from the
                // incoming FD, which means we never have to hand out our
                // sensitive internal FD. We still rely on a "bridge" being
                // inserted above to hold the session active.
                try {
                    final Int64Ref last = new Int64Ref(0);
                    FileUtils.copy(incomingFd.getFileDescriptor(), targetPfd.getFileDescriptor(),
                            lengthBytes, null, Runnable::run,
                            (long progress) -> {
                                if (params.sizeBytes > 0) {
                                    final long delta = progress - last.value;
                                    last.value = progress;
                                    synchronized (mProgressLock) {
                                        setClientProgressLocked(mClientProgress
                                                + (float) delta / (float) params.sizeBytes);
                                    }
                                }
                            });
                    // The caller cannot fsync this internal descriptor, so persist the copied
                    // bytes through it before the session hold is released and before this
                    // write can report success. An fsync failure fails the write. The directory
                    // entry and later renames are not covered here.
                    Os.fsync(targetPfd.getFileDescriptor());
                } finally {
                    IoUtils.closeQuietly(targetPfd);
                    IoUtils.closeQuietly(incomingFd);

                    // We're done here, so remove the "bridge" that was holding
                    // the session active.
                    synchronized (mLock) {
                        if (PackageInstaller.ENABLE_REVOCABLE_FD) {
                            mFds.remove(fd);
                        } else {
                            bridge.forceClose();
                            mBridges.remove(bridge);
                        }
                    }
                }
                return null;
            } else if (PackageInstaller.ENABLE_REVOCABLE_FD) {
                return createRevocableFdInternal(fd, targetPfd);
            } else {
                bridge.setTargetFile(targetPfd);
                bridge.start();
                return bridge.getClientSocket();
            }

        } catch (ErrnoException e) {
            throw e.rethrowAsIOException();
        }
    }

    /**
     * If anybody is reading or writing data of the session, throw an {@link SecurityException}.
     */
    @GuardedBy("mLock")
    private void assertNoWriteFileTransfersOpenLocked() {
        // Verify that all writers are hands-off
        for (RevocableFileDescriptor fd : mFds) {
            if (!fd.isRevoked()) {
                throw new SecurityException("Files still open");
            }
        }
        for (FileBridge bridge : mBridges) {
            if (!bridge.isClosed()) {
                throw new SecurityException("Files still open");
            }
        }
    }

