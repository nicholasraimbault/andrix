// SPDX-License-Identifier: Apache-2.0
package android.content;

/** Host model stub of a component name. */
public final class ComponentName {
    private final String pkg;
    private final String cls;

    public ComponentName(String pkg, String cls) {
        this.pkg = pkg;
        this.cls = cls;
    }

    public String getPackageName() {
        return pkg;
    }

    public String getClassName() {
        return cls;
    }

    public String flattenToShortString() {
        return pkg + "/" + (cls.startsWith(pkg + ".") ? cls.substring(pkg.length()) : cls);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ComponentName && ((ComponentName) other).pkg.equals(pkg)
                && ((ComponentName) other).cls.equals(cls);
    }

    @Override
    public int hashCode() {
        return pkg.hashCode() * 31 + cls.hashCode();
    }
}
