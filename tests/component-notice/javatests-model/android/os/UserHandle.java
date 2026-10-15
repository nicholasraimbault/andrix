// SPDX-License-Identifier: Apache-2.0
package android.os;

/** Host model stub of a user handle. */
public final class UserHandle {
    final int id;

    UserHandle(int id) {
        this.id = id;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof UserHandle && ((UserHandle) other).id == id;
    }

    @Override
    public int hashCode() {
        return id;
    }
}
