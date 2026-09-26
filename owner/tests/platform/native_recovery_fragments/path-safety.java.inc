    private static NativePrincipalRecovery withNativeCodePath(NativePrincipalRecovery view, File codePath) {
        return codePath != null && codePath.isAbsolute() ? view.retainCode(codePath)
                : view.withUnidentifiedCode();
    }

    private static NativePrincipalRecovery deferNativeName(NativePrincipalRecovery view, String name, File codePath) {
        return codePath == null || codePath.isAbsolute() ? view.defer(name, codePath)
                : view.defer(name, null).withUnidentifiedCode();
    }

