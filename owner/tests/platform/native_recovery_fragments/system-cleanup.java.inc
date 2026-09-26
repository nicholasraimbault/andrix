        for (int index = packageSettings.size() - 1; index >= 0; index--) {
            final PackageSetting ps = packageSettings.valueAt(index);
            final String packageName = ps.getPackageName();
            /*
             * If this is not a system app, it can't be a
             * disable system app.
             */
            if (!ps.isSystem()) {
                continue;
            }
            if (mPm.mSettings.isNativePrincipalPackageLPr(packageName)
                    || mPm.mSettings.isNativePrincipalAppIdLPr(ps.getAppId())) {
                mPm.mSettings.deferNativePackage(packageName, ps.getPath());
                continue;
            }

