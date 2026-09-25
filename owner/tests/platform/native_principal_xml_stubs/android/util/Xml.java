// SPDX-License-Identifier: Apache-2.0
// JDK text XML facade. It does not qualify Android's ABX reader/writer.
package android.util;

import com.android.modules.utils.TypedXmlPullParser;
import com.android.modules.utils.TypedXmlSerializer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

public final class Xml {
    public static TypedXmlPullParser resolvePullParser(InputStream stream) throws IOException {
        try {
            XMLInputFactory factory = XMLInputFactory.newFactory();
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
            return new Reader(factory.createXMLStreamReader(stream, "UTF-8"));
        } catch (XMLStreamException error) { throw new IOException(error); }
    }

    private static final class Reader implements TypedXmlPullParser {
        final XMLStreamReader input;
        int depth;
        int event = START_DOCUMENT;
        Reader(XMLStreamReader input) { this.input = input; }
        public int next() throws XmlPullParserException {
            if (event == END_TAG) depth--;
            try {
                while (input.hasNext()) {
                    int value = input.next();
                    if (value == XMLStreamConstants.START_ELEMENT) { depth++; return event = START_TAG; }
                    if (value == XMLStreamConstants.END_ELEMENT) return event = END_TAG;
                    if (value == XMLStreamConstants.END_DOCUMENT) return event = END_DOCUMENT;
                    if (value == XMLStreamConstants.CHARACTERS || value == XMLStreamConstants.CDATA) return event = TEXT;
                    if (value == XMLStreamConstants.DTD) throw new XmlPullParserException("DTD refused");
                }
                return event = END_DOCUMENT;
            } catch (XMLStreamException error) { throw new XmlPullParserException("XML", this, error); }
        }
        public int nextTag() throws XmlPullParserException {
            int value;
            do { value = next(); } while (value == TEXT && isWhitespace());
            if (value != START_TAG && value != END_TAG) throw new XmlPullParserException("Expected tag");
            return value;
        }
        public String getName() { return input.getLocalName(); }
        public int getEventType() { return event; }
        public int getDepth() { return depth; }
        public int getAttributeCount() { return input.getAttributeCount(); }
        public String getAttributeValue(String namespace, String name) { return input.getAttributeValue(namespace, name); }
        public boolean isWhitespace() { return input.isWhiteSpace(); }
        public int getAttributeInt(String namespace, String name) throws XmlPullParserException {
            try { return Integer.parseInt(getAttributeValue(namespace, name)); }
            catch (NumberFormatException error) { throw new XmlPullParserException("Invalid integer", this, error); }
        }
        public long getAttributeLong(String namespace, String name) throws XmlPullParserException {
            try { return Long.parseLong(getAttributeValue(namespace, name)); }
            catch (NumberFormatException error) { throw new XmlPullParserException("Invalid long", this, error); }
        }
        public boolean getAttributeBoolean(String namespace, String name) throws XmlPullParserException {
            String value = getAttributeValue(namespace, name);
            if ("true".equals(value)) return true;
            if ("false".equals(value)) return false;
            throw new XmlPullParserException("Invalid boolean");
        }
    }

    public static TypedXmlSerializer serializer(OutputStream stream) throws IOException {
        try {
            XMLStreamWriter out = XMLOutputFactory.newFactory().createXMLStreamWriter(stream, "UTF-8");
            return new TypedXmlSerializer() {
                public void startTag(String ns, String name) throws IOException {
                    try { out.writeStartElement(name); } catch (XMLStreamException e) { throw new IOException(e); }
                }
                public void endTag(String ns, String name) throws IOException {
                    try { out.writeEndElement(); out.flush(); } catch (XMLStreamException e) { throw new IOException(e); }
                }
                public void attribute(String ns, String name, String value) throws IOException {
                    try { out.writeAttribute(name, value); } catch (XMLStreamException e) { throw new IOException(e); }
                }
                public void attributeInt(String ns, String name, int value) throws IOException { attribute(ns, name, Integer.toString(value)); }
                public void attributeLong(String ns, String name, long value) throws IOException { attribute(ns, name, Long.toString(value)); }
                public void attributeBoolean(String ns, String name, boolean value) throws IOException { attribute(ns, name, Boolean.toString(value)); }
            };
        } catch (XMLStreamException error) { throw new IOException(error); }
    }
    private Xml() {}
}
