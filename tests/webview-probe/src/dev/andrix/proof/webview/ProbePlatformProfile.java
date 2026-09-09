package dev.andrix.proof.webview;

import java.util.Arrays;

/** Source-pinned PM metadata expectations, not permission grants or APK declarations. */
final class ProbePlatformProfile {
    static final String AOSP = "aosp17";
    static final String GRAPHENEOS = "grapheneos-2026081300";
    static final String GOS_PRODUCT = "andrix_gos_cf_arm64_only_phone";
    static final String GOS_FAMILY = "Andrix/" + GOS_PRODUCT + "/andrix_cf_arm64_only:17/";
    static final String OTHER_SENSORS = "android.permission.OTHER_SENSORS";
    private static final String INTERNET = "android.permission.INTERNET";
    private static final String LOCAL_NETWORK = "android.permission.ACCESS_LOCAL_NETWORK";

    final String name;

    private ProbePlatformProfile(String name) {
        this.name = name;
    }

    static ProbePlatformProfile parse(String name) {
        require(AOSP.equals(name) || GRAPHENEOS.equals(name), "Unknown platform_profile");
        return new ProbePlatformProfile(name);
    }

    String[] expectedApkPermissions() {
        return new String[] {INTERNET, LOCAL_NETWORK};
    }

    String[] expectedImplicitPmPermissions() {
        return GRAPHENEOS.equals(name) ? new String[] {OTHER_SENSORS} : new String[0];
    }

    void validate(String fingerprint, String product, int sdk, String[] permissions) {
        require(sdk == 37, "Expected Android API 37");
        require(fingerprint != null && product != null, "Missing platform identity");
        if (GRAPHENEOS.equals(name)) {
            require(GOS_PRODUCT.equals(product) && fingerprint.startsWith(GOS_FAMILY)
                    && fingerprint.substring(GOS_FAMILY.length()).matches(
                            "[^/]+/andrix\\.gos\\.2026081300\\.[0-9a-f]{7}:userdebug/test-keys"),
                    "GrapheneOS profile requires the pinned Andrix proof generation");
        } else {
            require(!fingerprint.startsWith(GOS_FAMILY) && !GOS_PRODUCT.equals(product),
                    "GrapheneOS proof requires explicit platform_profile");
        }

        String[] expected = GRAPHENEOS.equals(name)
                ? new String[] {INTERNET, LOCAL_NETWORK, OTHER_SENSORS}
                : expectedApkPermissions();
        require(permissions != null && permissions.length == expected.length,
                "Unexpected PackageManager permission metadata");
        String[] observed = permissions.clone();
        for (String permission : observed) {
            require(permission != null, "Null PackageManager permission metadata");
        }
        Arrays.sort(expected);
        Arrays.sort(observed);
        require(Arrays.equals(expected, observed), "Unexpected PackageManager permission metadata");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }
}
