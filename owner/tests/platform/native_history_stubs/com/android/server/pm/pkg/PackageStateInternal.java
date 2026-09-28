// SPDX-License-Identifier: Apache-2.0
// Host facade only. Not Android behavior or authority.
package com.android.server.pm.pkg;
import java.io.File;
public interface PackageStateInternal { String getPackageName(); File getPath(); }
