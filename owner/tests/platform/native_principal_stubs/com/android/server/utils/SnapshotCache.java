// SPDX-License-Identifier: Apache-2.0
// Host facade only. Not Android behavior or authority.
package com.android.server.utils;
public abstract class SnapshotCache<T> {
 public abstract T snapshot();
 public static final class Auto<T> extends SnapshotCache<T> {
  private final T value; public Auto(T v,Object watched,String name){value=v;}
  @SuppressWarnings("unchecked") public T snapshot(){
   if(value instanceof WatchedArrayList<?>)return (T)((WatchedArrayList<?>)value).snapshot();
   return (T)((WatchedSparseArray<?>)value).snapshot();
  }
 }
 public static final class Sealed<T> extends SnapshotCache<T> { public T snapshot(){throw new IllegalStateException();} }
}
