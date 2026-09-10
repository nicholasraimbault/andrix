// SPDX-License-Identifier: Apache-2.0
package dev.andrix.session;

import android.os.ParcelFileDescriptor;

parcelable Attachment {
    long generation;
    long sessionId;
    long firstOutputOffset;
    ParcelFileDescriptor stream;
}
