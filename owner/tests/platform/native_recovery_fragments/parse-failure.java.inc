            String packageName = result.parsedPackage == null ? null : result.parsedPackage.getPackageName();
            NativePrincipalRecovery recovery = mPm.mSettings.nativeRecoveryView();
            if (nativeDeferred || mPm.mSettings.isNativePrincipalPackageLPr(packageName)) {
                mPm.mSettings.deferNativePackage(packageName, result.scanFile);
                Slog.w(TAG, "Package scan deferred for native identity recovery; code retained");
                return;
            }
            if (recovery.protectsName(packageName) || recovery.defersName(packageName)
                    || recovery.keepsCodePath(result.scanFile)
                    || recovery.preservesUnidentifiedCode(result.scanFile,
                    Environment.getDataAppDirectory(StorageManager.UUID_PRIVATE_INTERNAL))) {
                // Unknown attribution retains code, not a claim that this
                // unrelated package has a native identity or mutation fence.
                mPm.mSettings.retainNativeCode(result.scanFile);
                return;
            }
