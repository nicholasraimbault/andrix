// SPDX-License-Identifier: Apache-2.0
package android.os;

import java.util.HashMap;
import java.util.Map;

/** Host model stub: the serial of each user the model knows, -1 for any other. */
public final class UserManager {
    public static final Map<Integer, Long> SERIALS = new HashMap<>();

    public long getSerialNumberForUser(UserHandle user) {
        Long serial = SERIALS.get(user.id);
        return serial == null ? -1 : serial;
    }
}
