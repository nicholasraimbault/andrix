// SPDX-License-Identifier: Apache-2.0
package android.os;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Host model stub of a Bundle: typed reads give a value only for its own type, as Android's. */
public final class Bundle {
    private final Map<String, Object> values = new LinkedHashMap<>();

    public void putBoolean(String key, boolean value) {
        values.put(key, value);
    }

    public boolean getBoolean(String key, boolean fallback) {
        Object v = values.get(key);
        return v instanceof Boolean ? (Boolean) v : fallback;
    }

    public void putString(String key, String value) {
        values.put(key, value);
    }

    public String getString(String key) {
        Object v = values.get(key);
        return v instanceof String ? (String) v : null;
    }

    public void putInt(String key, int value) {
        values.put(key, value);
    }

    public int getInt(String key, int fallback) {
        Object v = values.get(key);
        return v instanceof Integer ? (Integer) v : fallback;
    }

    public void putLong(String key, long value) {
        values.put(key, value);
    }

    public long getLong(String key, long fallback) {
        Object v = values.get(key);
        return v instanceof Long ? (Long) v : fallback;
    }

    public void putBinder(String key, IBinder value) {
        values.put(key, value);
    }

    public IBinder getBinder(String key) {
        Object v = values.get(key);
        return v instanceof IBinder ? (IBinder) v : null;
    }

    public void putAll(Bundle other) {
        values.putAll(other.values);
    }

    public Set<String> keySet() {
        return values.keySet();
    }

    public boolean isEmpty() {
        return values.isEmpty();
    }

    public int size() {
        return values.size();
    }
}
