package dev.andrix.proof.webviewqualification;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.SystemClock;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Read-only fields from the exact pinned third-party DEX, not Android hidden APIs. */
final class ConfigCheck {
    static void inspect(Context context, Session s, ClassLoader loader) throws Exception {
        s.requireRunning();
        PackageManager pm = context.getPackageManager();
        PackageInfo config = Pins.packageInfo(pm, Pins.CONFIG); // Missing package is never the negative.
        byte[] expectedPin = Pins.unhex(Pins.SIGNER);
        boolean trusted = pm.hasSigningCertificate(Pins.CONFIG, expectedPin,
                PackageManager.CERT_INPUT_SHA256);
        s.record("config_package", "observation", Pins.describe(config),
                "expected_pin_sha256", Pins.SIGNER, "pm_has_signing_certificate", trusted);

        // Class.forName(false) does not ask the parser to initialize. Field.get
        // occurs only AFTER real WebView initialization. No verifier invocation,
        // Context/PackageManager mock, field write or reflection outside this list.
        Class<?> pinClass = ownClass(loader, "WV.xr");
        Class<?> parserClass = ownClass(loader, "WV.op1");
        Class<?> parsedClass = ownClass(loader, "WV.mp1");
        Field pinField = field(pinClass, "a", byte[].class, true);
        Field futureField = parserClass.getDeclaredField("b");
        Arguments.check(Modifier.isStatic(futureField.getModifiers())
                        && Future.class.isAssignableFrom(futureField.getType()),
                "WV.op1.b is not the pinned static Future field");
        futureField.setAccessible(true);
        Field parsedField = field(parserClass, "c", parsedClass, true);
        Field versionField = field(parsedClass, "b", long.class, false);
        byte[] pin = (byte[]) pinField.get(null);
        String rawPin = pin == null ? null : Pins.hex(pin);
        s.record("compiled_config_pin", "class", pinClass.getName(), "field", "a",
                "byte_count", pin == null ? null : pin.length, "raw_hex", rawPin);
        Arguments.check(Pins.SIGNER.equals(rawPin), "Compiled config certificate pin mismatch");
        // Never retain or mutate the provider's byte[]; only compare its value.
        if (s.args.mode.equals("config-untrusted")) {
            snapshot(s, "after_initialization", futureField, parsedField, versionField);
            Arguments.check(!trusted, "Negative fixture unexpectedly has the trusted config signer");
            Arguments.check(futureField.get(null) == null && parsedField.get(null) == null,
                    "Wrong-signer config must leave BOTH parser Future and parsed object null");
            s.record("config_verdict", "trusted", false, "future_null", true, "parsed_null", true);
            return;
        }

        Arguments.check(trusted, "Baseline config does not have the compiled certificate pin");
        long deadline = SystemClock.elapsedRealtime() + TimeUnit.SECONDS.toMillis(Session.TIMEOUT_SECONDS);
        Future<?> observedFuture = null;
        Object futureValue = null;
        boolean futureChecked = false;
        snapshot(s, "after_initialization", futureField, parsedField, versionField);
        while (true) {
            s.requireRunning();
            Future<?> future = (Future<?>) futureField.get(null);
            Object parsed = parsedField.get(null);
            if (future != null && !futureChecked) {
                observedFuture = future;
                // Public java.util.concurrent API on a third-party Future. An
                // exceptional/cancelled Future FAILS, even if c looks populated.
                long remaining = deadline - SystemClock.elapsedRealtime();
                Arguments.check(remaining > 0, "Parser wait deadline expired");
                try {
                    futureValue = future.get(remaining, TimeUnit.MILLISECONDS);
                    Arguments.check(future.isDone() && !future.isCancelled(),
                            "Parser Future did not finish successfully");
                    futureChecked = true;
                } catch (Exception error) {
                    s.record("parser_future_failure", "exception", error.toString(),
                            "future_class", future.getClass().getName(),
                            "done", future.isDone(), "cancelled", future.isCancelled());
                    throw error;
                }
                continue; // Re-read c after Future completion (happens-before).
            }
            Arguments.check(future == null || future == observedFuture,
                    "Parser Future changed after initialization");
            if (parsed != null) {
                snapshot(s, "parsed", futureField, parsedField, versionField);
                long version = versionField.getLong(parsed);
                s.record("config_verdict", "trusted", true, "config_version", version,
                        "expected_config_version", s.args.configVersion,
                        "future_checked", futureChecked,
                        "future_result_null", futureValue == null,
                        "future_result_class", futureValue == null ? null : futureValue.getClass().getName(),
                        "future_failure", false);
                Arguments.check(version >= 0 && version == s.args.configVersion,
                        "Parsed config version mismatch");
                return;
            }
            Arguments.check(future != null, "Trusted initialization left both parser fields null");
            Arguments.check(SystemClock.elapsedRealtime() < deadline, "Parsed config remained null");
            Thread.sleep(50); // Worker only, bounded by the parser AND enclosing stage deadlines.
        }
    }

    private static Class<?> ownClass(ClassLoader loader, String name) throws Exception {
        Class<?> cls = Class.forName(name, false, loader);
        Arguments.check(cls.getClassLoader() == loader, "Pinned class not defined by WebView loader: " + name);
        return cls;
    }

    private static Field field(Class<?> cls, String name, Class<?> type, boolean isStatic)
            throws Exception {
        Field field = cls.getDeclaredField(name);
        Arguments.check(field.getType() == type
                        && Modifier.isStatic(field.getModifiers()) == isStatic,
                "Unexpected pinned field shape: " + cls.getName() + "." + name);
        field.setAccessible(true);
        return field;
    }

    private static void snapshot(Session s, String point, Field futureField,
            Field parsedField, Field versionField) throws Exception {
        Future<?> future = (Future<?>) futureField.get(null);
        Object parsed = parsedField.get(null);
        s.record("parser_fields", "point", point, "parser_class", "WV.op1",
                "future_field", "b", "parsed_field", "c",
                "future_null", future == null,
                "future_class", future == null ? null : future.getClass().getName(),
                "future_done", future == null ? null : future.isDone(),
                "future_cancelled", future == null ? null : future.isCancelled(),
                "parsed_null", parsed == null,
                "parsed_class", parsed == null ? null : parsed.getClass().getName(),
                "version_field", "WV.mp1.b",
                "config_version", parsed == null ? null : versionField.getLong(parsed));
    }
}
