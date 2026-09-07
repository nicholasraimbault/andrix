package dev.andrix.proof.webview;

/** Host-only URI contract tests. Documentation domains are parsed, never contacted. */
public final class ProbeConfigTest {
    private static final String GOOD = "https://good.example.org/generate_204";
    private static final String BAD = "https://wrong.example.org/generate_204";
    private static final String PROVIDER = "dev.andrix.experiment.webview";
    private static int checks;

    public static void main(String[] args) {
        ProbeConfig config = ProbeConfig.parse(GOOD, BAD, PROVIDER);
        check(GOOD.equals(config.goodUrl) && BAD.equals(config.badUrl)
                && "https://good.example.org".equals(config.goodOrigin)
                && PROVIDER.equals(config.expectedProvider));
        config = ProbeConfig.parse(GOOD.replace(".org/", ".org:8443/"),
                BAD.replace(".org/", ".org:8443/"), PROVIDER);
        check("https://good.example.org:8443".equals(config.goodOrigin));
        for (int port : new int[] {1, 65535}) {
            config = ProbeConfig.parse(GOOD.replace(".org/", ".org:" + port + "/"),
                    BAD.replace(".org/", ".org:" + port + "/"), PROVIDER);
            check(("https://good.example.org:" + port).equals(config.goodOrigin));
        }
        String longestLabel = "https://" + repeat('a', 63) + ".example.org/generate_204";
        check(longestLabel.equals(ProbeConfig.parse(longestLabel, BAD, PROVIDER).goodUrl));

        for (String invalid : new String[] {
                null, "", " " + GOOD, GOOD + " ", GOOD + "\n", GOOD + "\u007f",
                "http://good.example.org/generate_204", "HTTPS://good.example.org/generate_204",
                "https:good.example.org/generate_204", "//good.example.org/generate_204",
                "file:///generate_204", "data:text/html,probe", "javascript:42",
                "https://user@good.example.org/generate_204",
                "https://user:password@good.example.org/generate_204",
                GOOD + "?", GOOD + "?q=1", GOOD + "#", GOOD + "#fragment",
                "https://good.example.org", "https://good.example.org/",
                GOOD + "/", "https://good.example.org//generate_204",
                "https://good.example.org/a/../generate_204",
                "https://good.example.org/%67enerate_204",
                "https://good.example.org\\@wrong.example.org/generate_204",
                "https://good%2eexample.org/generate_204",
                "https://Good.example.org/generate_204", "https://good.example.org./generate_204",
                "https://g\u00f6od.example.org/generate_204", "https://good\u3002example.org/generate_204",
                "https://good..example.org/generate_204", "https://-good.example.org/generate_204",
                "https://good-.example.org/generate_204", "https://good_host.example.org/generate_204",
                "https://localhost/generate_204", "https://host.localhost/generate_204",
                "https://host.local/generate_204", "https://host.invalid/generate_204",
                "https://host.test/generate_204", "https://host.example/generate_204",
                "https://127.0.0.1/generate_204", "https://2130706433/generate_204",
                "https://0x7f000001/generate_204", "https://0177.0.0.1/generate_204",
                "https://[::1]/generate_204", "https://[fe80::1%25eth0]/generate_204",
                "https://good.example.org:/generate_204", "https://good.example.org:443/generate_204",
                "https://good.example.org:08443/generate_204", "https://good.example.org:0/generate_204",
                "https://good.example.org:-1/generate_204", "https://good.example.org:65536/generate_204",
                "https://" + repeat('a', 64) + ".example.org/generate_204",
                "https://" + repeat('a', 2048) + ".org/generate_204"}) {
            reject(invalid, BAD, PROVIDER);
            reject(GOOD, invalid, PROVIDER);
        }
        reject(GOOD, GOOD, PROVIDER);
        reject(GOOD, BAD.replace(".org/", ".org:8443/"), PROVIDER);
        for (String invalid : new String[] {
                null, "", "webview", "a..b", ".a.b", "a.b.", "a.1b", " a.b", "a.b\n",
                "a/b", "a-b.c", repeat('a', 256) + ".b"}) {
            reject(GOOD, BAD, invalid);
        }
        System.out.println("PASS: " + checks + " host-only config checks (no Android or network)");
    }

    private static void reject(String good, String bad, String provider) {
        try {
            ProbeConfig.parse(good, bad, provider);
        } catch (IllegalArgumentException expected) {
            checks++;
            return;
        }
        throw new AssertionError("Accepted invalid configuration: " + good + ", " + bad + ", " + provider);
    }

    private static void check(boolean value) {
        if (!value) {
            throw new AssertionError("Valid configuration changed");
        }
        checks++;
    }

    private static String repeat(char value, int count) {
        StringBuilder result = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            result.append(value);
        }
        return result.toString();
    }
}
