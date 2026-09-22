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

// Exact method fixture; checked by the pinned source adapter.
    @GuardedBy("mLock")
    private void enableFsVerityToAddedApksWithIdsig() throws PackageManagerException {
        try {
            long fsVerityEnabledApksSizeBytes = 0;
            List<File> files = getAddedApksLocked();
            for (var file : files) {
                if (new File(file.getPath() + V4Signature.EXT).exists()) {
                    VerityUtils.setUpFsverity(file.getPath());
                    fsVerityEnabledApksSizeBytes += file.length();
                }
            }
            if (fsVerityEnabledApksSizeBytes > 0) {
                synchronized (mMetrics) {
                    mMetrics.onFsVerityEnabledApksSizeBytesCalculated(fsVerityEnabledApksSizeBytes);
                }
            }
        } catch (IOException e) {
            throw new PrepareFailure(PackageManager.INSTALL_FAILED_BAD_SIGNATURE,
                    "Failed to enable fs-verity to verify with idsig: " + e);
        }
    }

