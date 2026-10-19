// SPDX-License-Identifier: Apache-2.0
// Host stub of android.content.pm.BaseParceledListSlice: package private, as in the framework, so
// the helper reaches getList only through the public subclass.
package android.content.pm;

import java.util.List;

abstract class BaseParceledListSlice<T> {
    private final List<T> list;

    BaseParceledListSlice(List<T> list) {
        this.list = list;
    }

    public List<T> getList() {
        andrixstub.Script.trace("getList()");
        return list;
    }
}
