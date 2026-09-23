// SPDX-License-Identifier: Apache-2.0
package org.json;
import java.util.LinkedHashMap;
import java.util.Map;
/** Host test value collector only. Not a JSON parser or Android serialization proof. */
public final class JSONObject {
    public static final Object NULL = new Object();
    private final Map<String, Object> values = new LinkedHashMap<>();
    public JSONObject put(String key, Object value) { values.put(key, value); return this; }
    public Object get(String key) { return values.get(key); }
}
