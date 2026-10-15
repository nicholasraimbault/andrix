// SPDX-License-Identifier: Apache-2.0
package android.app;

import android.os.Bundle;

/**
 * Host model stub of ActivityOptions: makeBasic, setShareIdentityEnabled and toBundle. As the
 * pinned toBundle does, the share identity key is set only when identity sharing was enabled.
 */
public class ActivityOptions {
    public static final String KEY_SHARE_IDENTITY = "android:activity.shareIdentity";
    private boolean shareIdentity;

    public static ActivityOptions makeBasic() {
        return new ActivityOptions();
    }

    public ActivityOptions setShareIdentityEnabled(boolean value) {
        shareIdentity = value;
        return this;
    }

    public Bundle toBundle() {
        Bundle b = new Bundle();
        if (shareIdentity) b.putBoolean(KEY_SHARE_IDENTITY, shareIdentity);
        return b;
    }
}
