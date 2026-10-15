// SPDX-License-Identifier: Apache-2.0
package android.database;

/** Host model stub of a cursor: its columns and rows. */
public interface Cursor {
    String[] getColumnNames();

    int getCount();

    Object get(int row, int column);
}
