// SPDX-License-Identifier: Apache-2.0
// Host facade. Not Android parsing, syscall, permission or integrity qualification.
package com.android.internal.util;
import org.xmlpull.v1.*;import java.io.IOException;
public final class XmlUtils {
 public static void skipCurrentTag(XmlPullParser in)throws IOException,XmlPullParserException {
  int depth=in.getDepth(),event;while((event=in.next())!=XmlPullParser.END_DOCUMENT){if(event==XmlPullParser.END_TAG&&in.getDepth()==depth)return;}
  throw new XmlPullParserException("truncated element");
 }
 private XmlUtils(){}
}
