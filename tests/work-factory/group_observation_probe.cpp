// SPDX-License-Identifier: Apache-2.0
// Host read-only driver for the exact observation code linked into the Android
// client.
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>

#include "group_observation.h"
using namespace andrix::factory_proof;
int main(int argc, char** argv) {
  GroupObservation invalid(-1);
  if (invalid.read() != GroupPopulation::Unknown) return 1;
  int temporary = open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  GroupObservation wrong_filesystem(temporary);
  if (temporary >= 0) close(temporary);
  if (wrong_filesystem.read() != GroupPopulation::Unknown) return 2;
  if (argc == 1) return 0;
  if (argc != 2) return 3;
  char* end = nullptr;
  errno = 0;
  long fd = strtol(argv[1], &end, 10);
  if (errno || !end || *end || fd < 0 || fd > INT_MAX) return 4;
  GroupObservation observation(static_cast<int>(fd));
  // Drop the borrowed input. Observation owns its exact duplicate.
  close(static_cast<int>(fd));
  for (;;) {
    puts(population_name(observation.read()));
    fflush(stdout);
    const int command = getchar();
    if (command == 'q') return 0;
    if (command != 'r') return 5;
  }
}
