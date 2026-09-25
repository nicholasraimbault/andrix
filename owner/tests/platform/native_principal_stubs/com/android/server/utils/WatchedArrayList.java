// SPDX-License-Identifier: Apache-2.0
// Host facade only. Not Android behavior or authority.
package com.android.server.utils;
import java.util.ArrayList;
public final class WatchedArrayList<T> {
 private final ArrayList<T> values=new ArrayList<>(); private boolean sealed;
 public int size(){return values.size();} public T get(int i){return values.get(i);}
 public void add(T v){if(sealed)throw new IllegalStateException();values.add(v);}
 public void set(int i,T v){if(sealed)throw new IllegalStateException();values.set(i,v);}
 public void registerObserver(Watcher w){}
 public WatchedArrayList<T> snapshot(){WatchedArrayList<T> s=new WatchedArrayList<>();s.values.addAll(values);s.sealed=true;return s;}
}
