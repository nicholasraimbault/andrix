// SPDX-License-Identifier: Apache-2.0
#include "guards.h"
#include "session_core.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <unistd.h>

using namespace andrix;

int main() {
  assert(authorized_console(10146, "u:r:andrix_terminal:s0:c146,c256,c512,c768"));
  assert(authorized_console(10146, "u:r:andrix_terminal:s0"));
  for (uint32_t uid : {0U, 1000U, 2000U, kOwnerUid, 9999U, 90000U, 110146U})
    assert(!authorized_console(uid, "u:r:andrix_terminal:s0"));
  for (auto sid : {"", "u:r:untrusted_app:s0", "u:r:andrix_terminal:s01",
                   "u:r:andrix_terminal_extra:s0", "u:r:andrix_owner:s0"})
    assert(!authorized_console(10146, sid));
  assert(valid_dimensions(24, 80));
  assert(!valid_dimensions(0, 80));
  assert(!valid_dimensions(24, 401));
  assert(!valid_dimensions(-1, 10));
  assert(!valid_dimensions(201, 10));
  assert(!valid_dimensions(2, 9));

  AttachmentGate gate;
  assert(!gate.live(100));
  assert(gate.attach(100, false, true, true) == 0);
  assert(gate.attach(100, true, false, true) == 0);
  assert(gate.attach(100, true, true, false) == 0);
  auto first = gate.attach(100, true, true, true);
  assert(first != 0 && gate.live(101));
  assert(gate.renew(first, 1000, true, true));
  assert(gate.live(2499));
  assert(!gate.live(2500));
  assert(!gate.renew(first, 2500, true, true));  // expired leases cannot revive
  auto second = gate.attach(3000, true, true, true);
  assert(second > first);
  assert(!gate.renew(first, 3100, true, true));
  assert(!gate.detach(first));
  assert(gate.live(3101));
  assert(!gate.renew(second, 3102, false, true));
  assert(!gate.live(3102));
  auto third = gate.attach(4000, true, true, true);
  assert(!gate.renew(third, 4001, true, false));
  auto fourth = gate.attach(5000, true, true, true);
  assert(fourth > third && gate.detach(fourth));
  assert(!gate.live(5000));
  assert(gate.attach(6000, true, true, true));
  assert(!gate.live(5999));  // impossible clock rollback fails closed
  assert(gate.attach(5999, true, true, true) == 0);
  assert(gate.attach(std::numeric_limits<uint64_t>::max() - 1, true, true, true) == 0);

  AttachmentGate exhausted(uint64_t(std::numeric_limits<int64_t>::max()));
  assert(exhausted.attach(1, true, true, true) == 0 && !exhausted.live(1));
  AttachmentGate epoch(12345);
  assert(epoch.attach(1, true, true, true) == 12346);

  OutputTail tail(4);
  tail.append("ab");
  assert(tail.peek(2) == "ab" && tail.dropped() == 0);
  tail.append(std::string("c\0de", 4));
  assert(tail.peek(99) == std::string("c\0de", 4));
  assert(tail.dropped() == 2 && tail.size() == 4);
  assert(!tail.consume(5) && tail.size() == 4);
  assert(tail.consume(2) && tail.peek(9) == "de");
  assert(tail.consume(2) && tail.size() == 0);
  tail.append(std::string(4096, 'x'));
  assert(tail.size() == 4 && tail.dropped() == 4094);
  OutputTail zero(0);
  zero.append("abc");
  assert(zero.size() == 0 && zero.dropped() == 3);

  // This host executable is not a simulated Android success. The real guards
  // must reject the ordinary host identity/resource profile and absent CE path.
  assert(getuid() != kOwnerUid);
  assert(!check_identity().empty());
  assert(!check_resource_bounds().empty());
  std::string error;
  assert(open_ce_home(&error) == -1 && !error.empty());
  error.clear();
  assert(!ce_key_present(-1, &error) && !error.empty());
  std::cout << "owner core host checks passed; Android runtime unqualified\n";
}
