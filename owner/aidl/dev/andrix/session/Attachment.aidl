// SPDX-License-Identifier: Apache-2.0
package dev.andrix.session;

import android.os.ParcelFileDescriptor;
import dev.andrix.session.WorkInfo;

parcelable Attachment {
    long generation;
    long sessionId;
    long firstOutputOffset;
    ParcelFileDescriptor stream;
    boolean kept; // Compatibility field; work metadata is independent of presentation.
    WorkInfo work;
}
