// SPDX-License-Identifier: Apache-2.0
package org.json;
import java.util.LinkedHashMap;
import java.util.Map;
/** Host output facade for strings, numbers and booleans. Not Android JSON proof. */
public final class JSONObject {
    private final Map<String, Object> values = new LinkedHashMap<>();
    public JSONObject put(String key, Object value) throws JSONException {
        if (!(value instanceof String || value instanceof Number || value instanceof Boolean)) {
            throw new JSONException("unsupported host value");
        }
        values.put(key, value); return this;
    }
    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
    @Override public String toString() {
        StringBuilder out = new StringBuilder("{");
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            if (out.length() != 1) out.append(',');
            out.append(quote(entry.getKey())).append(':');
            out.append(entry.getValue() instanceof String ? quote((String) entry.getValue()) : entry.getValue());
        }
        return out.append('}').toString();
    }
}
