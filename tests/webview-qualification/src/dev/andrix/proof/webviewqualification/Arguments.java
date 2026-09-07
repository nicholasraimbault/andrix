package dev.andrix.proof.webviewqualification;

import android.os.Bundle;

final class Arguments {
    final String mode;
    final String fingerprint;
    final String marker;
    final long configVersion;

    Arguments(Bundle args, boolean providerTarget) {
        mode = required(args, "mode");
        fingerprint = required(args, "expected_fingerprint");
        check(fingerprint.length() <= 256 && fingerprint.matches("[!-~]+"),
                "expected_fingerprint must be bounded printable ASCII without spaces");
        boolean providerMode;
        switch (mode) {
            case "different-uid":
            case "config-trusted":
            case "config-untrusted":
                providerMode = false;
                break;
            case "fast-on":
            case "fast-off":
            case "cleanup":
            case "job-stage":
            case "job-present":
            case "job-absent":
                providerMode = true;
                break;
            default:
                throw new IllegalArgumentException("Unknown explicit mode: " + mode);
        }
        check(providerMode == providerTarget, "Mode does not belong to this instrumentation target");
        marker = args.getString("marker");
        if (mode.startsWith("job-")) {
            required(args, "marker");
        }
        if (marker != null) {
            check(mode.startsWith("job-") || mode.equals("cleanup"),
                    "marker is only accepted for job modes or cleanup");
            check(marker.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,63}"),
                    "marker must be 1..64 ASCII letters/digits/dots/underscores/hyphens");
        }
        if (mode.equals("config-trusted")) {
            String version = required(args, "expected_config_version");
            check(version.matches("0|[1-9][0-9]{0,18}"), "Invalid expected_config_version");
            configVersion = Long.parseLong(version);
            check(configVersion >= 0, "Negative expected_config_version");
        } else {
            check(!args.containsKey("expected_config_version"),
                    "expected_config_version is only accepted for config-trusted");
            configVersion = -1;
        }
    }

    boolean configMode() {
        return mode.startsWith("config-");
    }

    private static String required(Bundle args, String name) {
        String value = args.getString(name);
        check(value != null && !value.isEmpty(), "Missing explicit " + name);
        return value;
    }

    static void check(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
