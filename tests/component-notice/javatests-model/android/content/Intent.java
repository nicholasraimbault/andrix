// SPDX-License-Identifier: Apache-2.0
package android.content;

import android.os.Bundle;

/** Host model stub of an intent: action, component, flags and typed extras. */
public class Intent {
    public static final int FLAG_ACTIVITY_NEW_TASK = 0x10000000;
    public static final int FLAG_ACTIVITY_CLEAR_TASK = 0x00008000;
    private final String action;
    private ComponentName component;
    private int flags;
    private final Bundle extras = new Bundle();

    public Intent(String action) {
        this.action = action;
    }

    public Intent setComponent(ComponentName value) {
        component = value;
        return this;
    }

    public Intent addFlags(int value) {
        flags |= value;
        return this;
    }

    public Intent putExtra(String key, String value) {
        extras.putString(key, value);
        return this;
    }

    public Intent putExtra(String key, int value) {
        extras.putInt(key, value);
        return this;
    }

    public Intent putExtra(String key, long value) {
        extras.putLong(key, value);
        return this;
    }

    public Intent putExtras(Bundle values) {
        extras.putAll(values);
        return this;
    }

    public String getAction() {
        return action;
    }

    public ComponentName getComponent() {
        return component;
    }

    public int getFlags() {
        return flags;
    }

    public Bundle getExtras() {
        return extras;
    }
}
