    private boolean claimInstallingPackageLocked(InstallRequest request, String packageName) {
        if (mInstallingPackageOwners.containsKey(request) || !mInstallingPackages.add(packageName)) return false;
        mInstallingPackageOwners.put(request, packageName);
        return true;
    }

    private void releaseInstallingPackageLocked(InstallRequest request) {
        String ownedName = mInstallingPackageOwners.remove(request);
        if (ownedName != null) mInstallingPackages.remove(ownedName);
    }

