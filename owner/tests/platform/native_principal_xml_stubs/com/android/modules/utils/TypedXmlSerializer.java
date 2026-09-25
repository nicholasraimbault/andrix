// SPDX-License-Identifier: Apache-2.0
// Host facade. Not Android parsing, syscall, permission or integrity qualification.
package com.android.modules.utils;
import java.io.IOException;
public interface TypedXmlSerializer {
 void startTag(String ns,String name) throws IOException;void endTag(String ns,String name) throws IOException;
 void attribute(String ns,String name,String value) throws IOException;
 void attributeInt(String ns,String name,int value) throws IOException;
 void attributeLong(String ns,String name,long value) throws IOException;
 void attributeBoolean(String ns,String name,boolean value) throws IOException;
}
