// SPDX-License-Identifier: Apache-2.0
// Host facade. Not Android parsing, syscall, permission or integrity qualification.
package org.xmlpull.v1;
public interface XmlPullParser {
 int START_DOCUMENT=0,END_DOCUMENT=1,START_TAG=2,END_TAG=3,TEXT=4;
 int next() throws java.io.IOException,XmlPullParserException;
 int nextTag() throws java.io.IOException,XmlPullParserException;
 String getName();int getEventType();int getDepth();int getAttributeCount();String getAttributeValue(String ns,String name);boolean isWhitespace();
}
