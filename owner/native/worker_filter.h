// SPDX-License-Identifier: Apache-2.0
#pragma once

namespace andrix {

// Additional restrictions for the new owner worker only. Must succeed before
// executing owner-controlled code. Does not filter the coordinator or Android.
bool install_worker_filter();

// Only for the separate ordinary Android principal path after trusted profile
// verification. Refuses reserved/isolated/root identities. Does not grant Binder
// permissions, change existing filters, or make arbitrary metadata authoritative.
bool install_principal_filter();

}  // namespace andrix
