// SPDX-License-Identifier: Apache-2.0
package android.os;

import java.util.ArrayList;
import java.util.List;

/**
 * Host model stub of a Parcel: an ordered list of written values, read back in order. An interface
 * token is written as a string and enforced against its descriptor, as Parcel.enforceInterface
 * refuses another one.
 */
public final class Parcel {
    private final List<Object> values = new ArrayList<>();
    private int position;
    public boolean recycled;

    public static Parcel obtain() {
        return new Parcel();
    }

    public void writeInterfaceToken(String descriptor) {
        values.add(descriptor);
    }

    public void enforceInterface(String descriptor) {
        Object token = position < values.size() ? values.get(position++) : null;
        if (!descriptor.equals(token)) throw new SecurityException("Binder invocation to an incorrect interface");
    }

    public void writeInt(int value) {
        values.add(value);
    }

    public int readInt() {
        Object value = position < values.size() ? values.get(position++) : null;
        return value instanceof Integer ? (Integer) value : 0;
    }

    public void writeString(String value) {
        values.add(value);
    }

    public String readString() {
        Object value = position < values.size() ? values.get(position++) : null;
        return value instanceof String ? (String) value : null;
    }

    public void setDataPosition(int at) {
        position = at;
    }

    public void recycle() {
        recycled = true;
    }
}
