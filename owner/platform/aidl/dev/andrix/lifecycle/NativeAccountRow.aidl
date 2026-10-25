// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lifecycle;

// An attributable historical account, never an unidentified UID hold or login name.
parcelable NativeAccountRow {
    const int BODY = 1;
    const int RESERVATION = 2;
    const int PENDING = 1;
    const int ACTIVE = 2;
    const int RETIRING_PIN = 3;
    const int NOT_PINNED = 4;
    const int LIFECYCLE_NOT_OBSERVED = 0;
    const int ELIGIBLE = 1;
    const int RETIRING = 2;
    const int RETIRED = 3;
    const int SUSPENSION_NOT_OBSERVED = 0;
    const int SUSPENSION_NONE = 1;
    const int SUSPENSION_PRESENT = 2;

    long principalId;
    int appId;
    String packageName;
    String lineage; // Stored 32 digit hex lineage. With user serial and principal ID names incarnation.
    int source; // Stored history, not a live subject.
    int phase; // Reservation pin, not lifecycle or execution permission.
    int lifecycle; // BODY records a lifecycle, a header reservation does not.
    // BODY records entries or their absence, a header does not. No actors, reasons, notes
    // or admission closure held only in memory.
    int suspension;
}
