// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.lifecycle;
import android.os.Bundle;
// Same-APK, non-exported probe only. Not a native owner lifecycle grant.
interface ILifecycleProbe {
    Bundle snapshot();
}
