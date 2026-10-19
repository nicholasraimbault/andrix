// SPDX-License-Identifier: Apache-2.0
// Host stub of android.os.UserHandle: a user ID.
package android.os;

public final class UserHandle {
    private final int id;

    public UserHandle(int id) {
        this.id = id;
    }

    public int getIdentifier() {
        return id;
    }
}
