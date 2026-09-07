package dev.andrix.proof.webview;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/** Deliberately narrow fixture URLs, not a general-purpose browser URL parser. */
final class ProbeConfig {
    final String goodUrl;
    final String badUrl;
    final String goodOrigin;
    final String expectedProvider;

    private ProbeConfig(URI good, URI bad, String provider) {
        goodUrl = good.toString();
        badUrl = bad.toString();
        goodOrigin = "https://" + good.getRawAuthority();
        expectedProvider = provider;
    }

    static ProbeConfig parse(String goodUrl, String badUrl, String provider) {
        URI good = fixtureUrl("good_url", goodUrl);
        URI bad = fixtureUrl("bad_url", badUrl);
        require(!good.getHost().equals(bad.getHost()), "good_url/bad_url need distinct hosts");
        require(good.getPort() == bad.getPort(), "good_url/bad_url need the same port");
        require(provider != null && provider.length() <= 255
                && provider.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"),
                "expected_provider must be an explicit package name");
        return new ProbeConfig(good, bad, provider);
    }

    private static URI fixtureUrl(String name, String value) {
        require(value != null && !value.isEmpty() && value.length() <= 2048,
                name + " is required (maximum 2048 ASCII characters)");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            require(c > 0x20 && c < 0x7f && c != '\\' && c != '%',
                    name + " disallows whitespace, non-ASCII, backslashes and escapes");
        }
        final URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException error) {
            throw new IllegalArgumentException(name + " is not a URI", error);
        }
        require("https".equals(uri.getScheme()) && !uri.isOpaque(),
                name + " requires canonical https://");
        require(uri.getRawUserInfo() == null && uri.getRawQuery() == null
                && uri.getRawFragment() == null, name + " disallows userinfo, query and fragment");
        require("/generate_204".equals(uri.getRawPath()),
                name + " must use exactly /generate_204");
        String host = uri.getHost();
        require(host != null && host.length() <= 253 && host.equals(host.toLowerCase(Locale.ROOT)),
                name + " requires a lowercase ASCII DNS host");
        String[] labels = host.split("\\.", -1);
        require(labels.length >= 2, name + " requires a fully qualified DNS host, not an IP");
        for (String label : labels) {
            require(label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"),
                    name + " has an invalid DNS label");
        }
        String tld = labels[labels.length - 1];
        require(tld.matches("[a-z]{2,63}") && !tld.equals("localhost")
                && !tld.equals("local") && !tld.equals("invalid") && !tld.equals("test")
                && !tld.equals("example"), name + " requires a non-local DNS suffix, not an IP");
        int port = uri.getPort();
        require(port == -1 || (port > 0 && port <= 65535 && port != 443),
                name + " needs port 1..65535; omit the default :443");
        String authority = host + (port == -1 ? "" : ":" + port);
        require(authority.equals(uri.getRawAuthority())
                && value.equals("https://" + authority + "/generate_204"),
                name + " must be canonical (no empty/zero-padded port or alternate spelling)");
        return uri;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }
}
