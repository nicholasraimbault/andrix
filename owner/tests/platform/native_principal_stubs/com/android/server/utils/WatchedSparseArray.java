// SPDX-License-Identifier: Apache-2.0
// Host facade only. Not Android behavior or authority.
package com.android.server.utils;
import java.util.HashMap;
public final class WatchedSparseArray<T> {
 private final HashMap<Integer,T> values=new HashMap<>(); private boolean sealed;
 public T get(int i){return values.get(i);}
 public void put(int i,T v){if(sealed)throw new IllegalStateException();values.put(i,v);}
 public void remove(int i){if(sealed)throw new IllegalStateException();values.remove(i);}
 public void registerObserver(Watcher w){}
 public WatchedSparseArray<T> snapshot(){WatchedSparseArray<T> s=new WatchedSparseArray<>();s.values.putAll(values);s.sealed=true;return s;}
}
