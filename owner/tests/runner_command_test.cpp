// SPDX-License-Identifier: Apache-2.0
#include "runner_command.h"
#include <cassert>
#include <iostream>
using namespace andrix;
int main() {
  const char* plain[] = {"runner", nullptr};
  assert(runner_command(1, plain, false).mode == RunnerMode::Plain);
  const char* create[] = {"runner", "--tmux-new", "42", nullptr};
  const char* attach[] = {"runner", "--tmux-attach", "9223372036854775807", nullptr};
  assert(runner_command(3, create, false).mode == RunnerMode::Invalid);
  assert(runner_command(3, create, true).mode == RunnerMode::TmuxNew);
  assert(runner_command(3, create, true).socket_name == "andrix-42");
  assert(runner_command(3, attach, true).mode == RunnerMode::TmuxAttach);
  for (const char* id : {"", "0", "01", "-1", "+1", " 1", "1 ", "1x", "../x", "9223372036854775808", "99999999999999999999"}) {
    const char* args[] = {"runner", "--tmux-new", id, nullptr};
    assert(runner_command(3, args, true).mode == RunnerMode::Invalid);
  }
  const char* invalid[] = {"runner", "--tmux-new", nullptr};
  assert(runner_command(3, invalid, true).mode == RunnerMode::Invalid);
  assert(runner_command(3, nullptr, true).mode == RunnerMode::Invalid);
  assert(runner_command(2, create, true).mode == RunnerMode::Invalid);
  std::cout << "Fixed owner runner mode/namespace tests passed; Android unqualified\n";
}
