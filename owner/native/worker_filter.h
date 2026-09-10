// SPDX-License-Identifier: Apache-2.0
#pragma once

namespace andrix {

// Additional restrictions for the new owner worker only. Must succeed before
// executing owner-controlled code. Does not filter the coordinator or Android.
bool install_worker_filter();

}  // namespace andrix
