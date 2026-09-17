// SPDX-License-Identifier: Apache-2.0
#pragma once
namespace andrix::factory_proof {
enum class GroupPopulation { Unknown, Populated, Empty, Removed };
// Owns a duplicate of the captured real cgroup directory FD. A missing core
// file means Removed only after this same object supplied valid population
// evidence. Failed reads/permissions and a never-observed directory remain
// Unknown.
class GroupObservation {
 public:
  explicit GroupObservation(int directory);
  ~GroupObservation();
  GroupObservation(const GroupObservation&) = delete;
  GroupObservation& operator=(const GroupObservation&) = delete;
  GroupPopulation read();

 private:
  int directory_;
  bool observed_ = false;
};
const char* population_name(GroupPopulation value);
}  // namespace andrix::factory_proof
