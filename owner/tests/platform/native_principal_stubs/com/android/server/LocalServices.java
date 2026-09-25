// SPDX-License-Identifier: Apache-2.0
// Host facade only. Not Android behavior or authority.
package com.android.server;
import java.util.HashMap;
public final class LocalServices {
 private static final HashMap<Class<?>,Object> services=new HashMap<>();
 public static <T> T getService(Class<T> type){return type.cast(services.get(type));}
 public static <T> void addService(Class<T> type,T value){services.put(type,value);}
 private LocalServices(){}
}
