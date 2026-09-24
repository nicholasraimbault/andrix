// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.principal;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/** Host parser checks only. They make no Android runtime, location or permission claim. */
public final class LocationArgumentsTest {
    private static int checks;

    private static void need(boolean value) {
        checks++;
        if (!value) throw new AssertionError("check " + checks);
    }

    private static String[] input(String... values) {
        return values;
    }

    /** Builds text from numeric code points, so this source file stays plain ASCII. */
    private static String text(int... codePoints) {
        return new String(codePoints, 0, codePoints.length);
    }

    private static void accepts(String[] args, String action, String nonce, int millis) {
        checks++;
        LocationArguments parsed;
        try {
            parsed = LocationArguments.parse(args);
        } catch (RuntimeException refusal) {
            throw new AssertionError("unexpected refusal at check " + checks, refusal);
        }
        if (!action.equals(parsed.action) || !nonce.equals(parsed.nonce)
                || parsed.durationMillis != millis) {
            throw new AssertionError("wrong result at check " + checks);
        }
    }

    /**
     * Requires exactly IllegalArgumentException, so an incidental NumberFormatException
     * cannot stand in for the explicit syntax checks. The message must be printable
     * ASCII, so refused input cannot carry control characters into logs.
     */
    private static void refused(String[] args) {
        checks++;
        try {
            LocationArguments.parse(args);
        } catch (RuntimeException refusal) {
            if (refusal.getClass() != IllegalArgumentException.class) {
                throw new AssertionError("wrong refusal type at check " + checks, refusal);
            }
            String message = refusal.getMessage();
            if (message == null || !message.matches("[ -~]+")) {
                throw new AssertionError("unsafe refusal message at check " + checks);
            }
            return;
        }
        throw new AssertionError("expected refusal at check " + checks);
    }

    /** Immutable value, private construction, fixed provider and no setters. */
    private static void checkShape() throws ReflectiveOperationException {
        Class<LocationArguments> type = LocationArguments.class;
        need(Modifier.isFinal(type.getModifiers()));
        for (Constructor<?> constructor : type.getDeclaredConstructors()) {
            if (!constructor.isSynthetic()) need(Modifier.isPrivate(constructor.getModifiers()));
        }
        int instanceFields = 0;
        for (Field field : type.getDeclaredFields()) {
            if (field.isSynthetic()) continue; // Coverage tools may add synthetic fields.
            need(Modifier.isFinal(field.getModifiers()));
            if (!Modifier.isStatic(field.getModifiers())) instanceFields++;
        }
        need(instanceFields == 3);
        String[] names = {"action", "nonce", "durationMillis"};
        Class<?>[] types = {String.class, String.class, int.class};
        for (int i = 0; i < names.length; i++) {
            Field field = type.getDeclaredField(names[i]);
            need(field.getType() == types[i] && !Modifier.isStatic(field.getModifiers()));
        }
        Field provider = type.getDeclaredField("PROVIDER");
        int modifiers = provider.getModifiers();
        need(Modifier.isPublic(modifiers) && Modifier.isStatic(modifiers)
                && Modifier.isFinal(modifiers)
                && "andrix_principal_test".equals(provider.get(null)));
        Method parse = type.getDeclaredMethod("parse", String[].class);
        need(Modifier.isPublic(parse.getModifiers()) && Modifier.isStatic(parse.getModifiers())
                && parse.getReturnType() == type);
        for (Method method : type.getDeclaredMethods()) {
            if (!method.isSynthetic()) need(!method.getName().startsWith("set"));
        }
    }

    public static void main(String[] ignored) throws ReflectiveOperationException {
        // Defaults.
        accepts(input("info", "request_01"), "info", "request_01", 0);
        accepts(input("watch", "request_01"), "watch", "request_01", 180000);

        // Explicit durations at and inside the bounds.
        accepts(input("info", "n", "0"), "info", "n", 0);
        accepts(input("watch", "n", "1000"), "watch", "n", 1000);
        accepts(input("watch", "n", "1001"), "watch", "n", 1001);
        accepts(input("watch", "n", "180000"), "watch", "n", 180000);
        accepts(input("watch", "n", "299999"), "watch", "n", 299999);
        accepts(input("watch", "n", "300000"), "watch", "n", 300000);

        // Leading zeros stay within 1 to 6 digits and read as decimal, not octal.
        accepts(input("info", "n", "000000"), "info", "n", 0);
        accepts(input("watch", "n", "001000"), "watch", "n", 1000);
        accepts(input("watch", "n", "010000"), "watch", "n", 10000);

        // Nonce alphabet and length bounds.
        for (String nonce : new String[] {"n", "_", "0", "Z", "AZaz09_", "n".repeat(64)}) {
            accepts(input("info", nonce), "info", nonce, 0);
            accepts(input("watch", nonce, "1000"), "watch", nonce, 1000);
        }

        // Two elements are always action and nonce, so an all digit nonce stays a nonce.
        accepts(input("watch", "1000"), "watch", "1000", 180000);

        // The provider is fixed. Provider names are refused as actions, durations or a
        // fourth element. In the nonce position a provider name is only a label.
        need("andrix_principal_test".equals(LocationArguments.PROVIDER));
        for (String provider : new String[] {"gps", "fused", "network", "passive",
                LocationArguments.PROVIDER}) {
            accepts(input("watch", provider), "watch", provider, 180000);
            refused(input(provider, "n"));
            refused(input("watch", "n", provider));
            refused(input("watch", "n", "1000", provider));
        }

        // Parsed values do not follow later changes to the caller's array.
        String[] mutable = input("watch", "before", "1000");
        LocationArguments kept = LocationArguments.parse(mutable);
        mutable[0] = "info";
        mutable[1] = "after";
        mutable[2] = "0";
        need(kept.action.equals("watch") && kept.nonce.equals("before")
                && kept.durationMillis == 1000);

        // Null input, null elements, too few and too many elements.
        refused(null);
        refused(input());
        refused(input("info"));
        refused(input("watch"));
        refused(input((String) null));
        refused(input(null, "n"));
        refused(input("info", null));
        refused(input("watch", null, "1000"));
        refused(input("info", "n", null));
        refused(input("watch", "n", null));
        refused(input(null, null, null));
        refused(input("info", "n", "0", "0"));
        refused(input("watch", "n", "1000", "extra"));
        refused(input("watch", "n", "1000", null));
        refused(new String[100]);

        // Actions are exact lower case ASCII words. The code points are NUL and
        // Cyrillic lookalikes for i and a.
        for (String bad : new String[] {"", " ", "INFO", "Info", "WATCH", "Watch", " info",
                "info ", "watch\n", "\nwatch", "watch\r\n", "watch\t", "watch" + text(0),
                "inf", "infos", "watching", "info;id", "watch && id",
                text(0x456, 'n', 'f', 'o'), text('w', 0x430, 't', 'c', 'h'), "n",
                "post", "cancel", "observe", "grant"}) {
            refused(input(bad, "n"));
            refused(input(bad, "n", "1000"));
        }

        // Nonces are 1 to 64 ASCII letters, digits or underscores. The code points are
        // NUL, no break space, line separator, accented e, fullwidth n, Arabic Indic
        // one and mathematical bold n.
        for (String bad : new String[] {"", " ", " n", "n ", "n n", "\tn", "n\n", "\nn",
                "n\r\n", "n" + text(0), "n" + text(0xa0), "n" + text(0x2028), "n-1", "n.1",
                "n/1", "../n", "n;id", "$(id)", "`id`", "n|id", "n'", "n\"", "n=1", "n%0a",
                text(0xe9), text(0xff4e), text(0x661), text(0x1d427), "n".repeat(65),
                "n".repeat(4096)}) {
            refused(input("info", bad));
            refused(input("watch", bad, "1000"));
        }

        // An explicit info duration must be 0.
        for (String bad : new String[] {"1", "999", "1000", "180000", "300000", "999999"}) {
            refused(input("info", "n", bad));
        }

        // Watch durations stay from 1000 to 300000 inclusive.
        for (String bad : new String[] {"0", "000000", "1", "999", "000999", "300001",
                "999999"}) {
            refused(input("watch", "n", bad));
        }

        // Durations are 1 to 6 ASCII decimal digits with no sign, space, separator,
        // suffix or other digit script. Longer input is refused before any overflow.
        // The code points are minus sign, no break space, figure space, line separator,
        // next line, NUL, and 1000 in fullwidth, Arabic Indic and Devanagari digits.
        for (String bad : new String[] {"", " ", "\n", "+0", "-0", "+1000", "-1000",
                text(0x2212) + "1000", "-2147483648", " 1000", "1000 ", "\t1000", "1000\n",
                "\n1000", "1000\r\n", "1000" + text(0xa0), text(0x2007) + "1000",
                "1000" + text(0x2028), "1000" + text(0x85), "1000" + text(0), "1_000",
                "1,000", "1.000", "1000.0", "1e3", "0x3E8", "0b1111101000", "NaN",
                "Infinity", "1000ms", text(0xff11, 0xff10, 0xff10, 0xff10),
                text(0x661, 0x660, 0x660, 0x660), text(0x967, 0x966, 0x966, 0x966),
                "0000000", "0001000", "1000000", "2147483647", "2147483648", "4294968296",
                "18446744073709552616", "9".repeat(64)}) {
            refused(input("info", "n", bad));
            refused(input("watch", "n", bad));
        }

        checkShape();

        System.out.println("LOCATION_ARGUMENTS_PASS checks=" + checks
                + " no_Android_runtime_location_or_permission_claim");
    }
}
