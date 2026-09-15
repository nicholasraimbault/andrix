// SPDX-License-Identifier: Apache-2.0
// Explicit host facade; not Android identity or storage authority.
package android.content;
public class Context {
    public android.os.storage.StorageManager storage = new android.os.storage.StorageManager();
    public <T> T getSystemService(Class<T> type) { return type.cast(storage); }
}
