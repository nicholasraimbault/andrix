// SPDX-License-Identifier: Apache-2.0
// Host facade only. Not Android behavior or authority.
package com.android.server.pm;
import java.util.concurrent.locks.ReentrantLock;
final class PackageManagerTracedLock implements AutoCloseable {
 private final ReentrantLock lock=new ReentrantLock();
 PackageManagerTracedLock acquireLock(){lock.lock();return this;}
 public void close(){lock.unlock();}
}
