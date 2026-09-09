package dev.andrix.proof.webview;

/** Real pure-Java profile checks; no Android, permission operation, network or device. */
public final class ProbePlatformProfileTest {
    private static final String INTERNET = "android.permission.INTERNET";
    private static final String LOCAL = "android.permission.ACCESS_LOCAL_NETWORK";
    private static final String SENSORS = ProbePlatformProfile.OTHER_SENSORS;
    private static final String FP = ProbePlatformProfile.GOS_FAMILY
            + "CP2A.260605.016/andrix.gos.2026081300.108d857:userdebug/test-keys";
    private static int checks;

    public static void main(String[] args) {
        ProbePlatformProfile legacy = ProbePlatformProfile.parse("aosp17");
        ProbePlatformProfile gos = ProbePlatformProfile.parse("grapheneos-2026081300");
        legacy.validate("host-fixture-aosp", "aosp", 37, new String[] {INTERNET, LOCAL});
        legacy.validate("host-fixture-aosp", "aosp", 37, new String[] {LOCAL, INTERNET});
        gos.validate(FP, ProbePlatformProfile.GOS_PRODUCT, 37,
                new String[] {INTERNET, SENSORS, LOCAL});
        String[] permissions = {SENSORS, INTERNET, LOCAL};
        gos.validate(FP, ProbePlatformProfile.GOS_PRODUCT, 37, permissions);
        check(SENSORS.equals(permissions[0])); // validation never changes PM metadata
        check(gos.expectedApkPermissions().length == 2 && legacy.expectedApkPermissions().length == 2);
        check(gos.expectedImplicitPmPermissions().length == 1 && legacy.expectedImplicitPmPermissions().length == 0);
        for (String profile : new String[] {null, "", "grapheneos", "skip-permissions", "aosp18"}) {
            reject(() -> ProbePlatformProfile.parse(profile));
        }
        reject(() -> legacy.validate(FP, ProbePlatformProfile.GOS_PRODUCT, 37,
                new String[] {INTERNET, LOCAL}));
        reject(() -> legacy.validate("other", ProbePlatformProfile.GOS_PRODUCT, 37,
                new String[] {INTERNET, LOCAL}));
        reject(() -> legacy.validate(FP, "other", 37, new String[] {INTERNET, LOCAL}));
        for (String fingerprint : new String[] {null, "", "other", FP.replace("2026081300", "2026081301"),
                FP.replace(":17/", ":16/"), FP.replace("108d857", "wrong"), FP + "extra"}) {
            reject(() -> gos.validate(fingerprint, ProbePlatformProfile.GOS_PRODUCT, 37,
                    new String[] {INTERNET, LOCAL, SENSORS}));
        }
        for (String product : new String[] {null, "", "aosp", "andrix_cf_arm64_only_phone"}) {
            reject(() -> gos.validate(FP, product, 37, new String[] {INTERNET, LOCAL, SENSORS}));
        }
        for (int sdk : new int[] {0, 36, 38}) {
            reject(() -> gos.validate(FP, ProbePlatformProfile.GOS_PRODUCT, sdk,
                    new String[] {INTERNET, LOCAL, SENSORS}));
            reject(() -> legacy.validate("other", "other", sdk, new String[] {INTERNET, LOCAL}));
        }
        for (String[] observed : new String[][] {null, {}, {INTERNET}, {INTERNET, LOCAL},
                {INTERNET, LOCAL, LOCAL}, {INTERNET, SENSORS, SENSORS}, {INTERNET, LOCAL, null},
                {INTERNET, LOCAL, "android.permission.CAMERA"}, {INTERNET, LOCAL, SENSORS, SENSORS}}) {
            reject(() -> gos.validate(FP, ProbePlatformProfile.GOS_PRODUCT, 37, observed));
        }
        for (String[] observed : new String[][] {null, {}, {INTERNET}, {INTERNET, INTERNET},
                {INTERNET, null}, {INTERNET, LOCAL, SENSORS}, {INTERNET, "android.permission.CAMERA"}}) {
            reject(() -> legacy.validate("other", "other", 37, observed));
        }
        System.out.println("PASS: " + checks + " host-only platform-profile checks (no Android/network)");
    }

    private static void reject(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            checks++;
            return;
        }
        throw new AssertionError("Invalid profile/platform/permission metadata accepted");
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("Valid profile contract changed");
        checks++;
    }
}
