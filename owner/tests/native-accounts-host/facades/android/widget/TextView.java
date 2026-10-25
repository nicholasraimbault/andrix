// SPDX-License-Identifier: Apache-2.0
// Host test input only. Not an Android build input.
package android.widget;
public final class TextView {
    private volatile CharSequence text="";
    public void setText(CharSequence value) { text=value; }
    public String textForHostTest() { return text.toString(); }
}
