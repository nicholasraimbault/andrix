// SPDX-License-Identifier: Apache-2.0
// Host facade. Not Android parsing, syscall, permission or integrity qualification.
package com.android.modules.utils;
import org.xmlpull.v1.*;
public interface TypedXmlPullParser extends XmlPullParser {
 int getAttributeInt(String ns,String name) throws XmlPullParserException;
 long getAttributeLong(String ns,String name) throws XmlPullParserException;
 boolean getAttributeBoolean(String ns,String name) throws XmlPullParserException;
}
