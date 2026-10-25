// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lifecycle;

import dev.andrix.lifecycle.NativeAccountSnapshot;

// One authenticated Console caller, always its own Android user. No target IDs or effects.
interface INativeAccountQuery {
    NativeAccountSnapshot inspectCurrentUser();
}
