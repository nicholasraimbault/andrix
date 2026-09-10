// SPDX-License-Identifier: Apache-2.0
package dev.andrix.session;

import android.os.ParcelFileDescriptor;

parcelable Attachment {
    long generation;
    ParcelFileDescriptor stream;
}
