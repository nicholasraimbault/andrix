                        if (!mDeletePackageHelper.deletePackageLIF(
                                parsedPackage.getPackageName(), null, true,
                                mPm.mUserManager.getUserIds(), 0, new PackageRemovedInfo(), false,
                                Process.SYSTEM_UID)) {
                            // A refusal is not removal. Never let the system
                            // APK inherit the preserved data package's UID.
                            throw PackageManagerException.ofInternalError("Data package removal was refused",
                                    PackageManagerException.INTERNAL_ERROR_NATIVE_IDENTITY_DEFERRED);
                        }
