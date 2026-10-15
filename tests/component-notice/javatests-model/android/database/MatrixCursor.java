// SPDX-License-Identifier: Apache-2.0
package android.database;

import java.util.ArrayList;
import java.util.List;

/** Host model stub of MatrixCursor. */
public class MatrixCursor implements Cursor {
    private final String[] columns;
    private final List<Object[]> rows = new ArrayList<>();

    public MatrixCursor(String[] columns, int capacity) {
        this.columns = columns.clone();
    }

    public void addRow(Object[] values) {
        if (values.length != columns.length) throw new IllegalArgumentException("columns");
        rows.add(values.clone());
    }

    @Override
    public String[] getColumnNames() {
        return columns.clone();
    }

    @Override
    public int getCount() {
        return rows.size();
    }

    @Override
    public Object get(int row, int column) {
        return rows.get(row)[column];
    }
}
