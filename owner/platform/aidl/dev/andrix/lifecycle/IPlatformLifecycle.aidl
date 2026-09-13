// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lifecycle;

import dev.andrix.lifecycle.PlatformState;

// Local experimental API. Only the native coordinator is allowed to discover
// and query it. No user/key management, keep consent or terminal access operation.
interface IPlatformLifecycle {
    PlatformState snapshot();
}
