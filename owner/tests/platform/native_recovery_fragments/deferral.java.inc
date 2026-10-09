    void deferNativePackage(String packageName, File codePath) {
        synchronized (mLock) {
            if (codePath != null && !codePath.isAbsolute()) {
                mNativeRecoveryView = mNativeRecoveryView.defer(packageName, null).withUnidentifiedCode();
            } else mNativeRecoveryView = mNativeRecoveryView.defer(packageName, codePath);
        }
    }
