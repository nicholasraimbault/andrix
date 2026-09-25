// SPDX-License-Identifier: Apache-2.0
// Host facade. Not Android parsing, syscall, permission or integrity qualification.
package org.xmlpull.v1;
public final class XmlPullParserException extends Exception {
 private static final long serialVersionUID=1L;
 public XmlPullParserException(String message){super(message);}
 public XmlPullParserException(String message,XmlPullParser parser,Throwable cause){super(message,cause);}
}
