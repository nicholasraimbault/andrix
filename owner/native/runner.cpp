// SPDX-License-Identifier: Apache-2.0
#include "guards.h"
#include "session_core.h"
#include "worker_filter.h"
#include "runner_command.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace {
[[noreturn]] void fail(const std::string& text) {
  dprintf(STDERR_FILENO, "andrix session admission failed: %s\n", text.c_str());
  _exit(126);
}
}

int main(int argc, char** argv) {
#ifdef ANDRIX_OWNER_KEEP
  constexpr bool keep_enabled = true;
#else
  constexpr bool keep_enabled = false;
#endif
  const auto command = andrix::runner_command(argc, argv, keep_enabled);
  if (command.mode == andrix::RunnerMode::Invalid) fail("invalid fixed runner mode");
  auto identity = andrix::check_identity();
  if (!identity.empty()) fail(identity);
  pid_t coordinator = getppid();
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != coordinator) fail("coordinator disappeared");
  // A fork from a Binder transaction must not keep its transient donated priority.
  if (setpriority(PRIO_PROCESS, 0, 10) != 0) fail("background priority");
  auto bounds = andrix::check_resource_bounds(coordinator);
  if (!bounds.empty()) fail(bounds);
  // Before any owner code: no set-id/file-cap privilege gain, direct Binder
  // transactions or io_uring. Keep this restriction local to the owner worker.
  if (!andrix::install_worker_filter()) fail("worker syscall restriction unavailable");
  if (setsid() < 0 || ioctl(STDIN_FILENO, TIOCSCTTY, 0) != 0 ||
      tcsetpgrp(STDIN_FILENO, getpgrp()) != 0) fail("controlling PTY setup");
  std::string error;
  int home = andrix::open_ce_home(&error);
  if (home < 0 || fchdir(home) != 0) fail(error.empty() ? "home chdir" : error);
  close(home);
  umask(0077);
  if (mkdir(".tmp", 0700) != 0 && errno != EEXIST) fail("home temporary directory");
  struct stat st{};
  if (lstat(".tmp", &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != andrix::kOwnerUid ||
      (st.st_mode & 07777) != 0700) fail("unsafe temporary directory");
  // Deliberately constructed environment. No client-supplied LD_*, ENV or startup
  // file variables. Bionic's normal allocator/hardening selection is untouched.
  char path[] = "PATH=/usr/bin:/system/bin";
  char home_var[] = "HOME=/data/misc_ce/0/andrix";
  char temporary[] = "TMPDIR=/data/misc_ce/0/andrix/.tmp";
  // tmux deliberately uses its own variable, not the generic TMPDIR fallback.
  // Keep its named socket directory in the already validated private CE tree.
  char tmux_temporary[] = "TMUX_TMPDIR=/data/misc_ce/0/andrix/.tmp";
  char term[] = "TERM=xterm-256color";
  char user[] = "USER=system_ext_andrix";
  char login[] = "LOGNAME=system_ext_andrix";
  char shell[] = "SHELL=/system/bin/sh";
  char prompt[] = "PS1=andrix$ ";
  char lang[] = "LANG=C.UTF-8";
  char* environment[] = {path, home_var, temporary, tmux_temporary, term, user, login, shell, prompt, lang, nullptr};
  char executable[] = "/system/bin/sh";
  char interactive[] = "-i";
  char* arguments[] = {executable, interactive, nullptr};
#ifdef ANDRIX_OWNER_KEEP
  if (command.mode != andrix::RunnerMode::Plain) {
    // Only a fixed native work namespace and fixed commands. Reattachment never
    // uses new-session -A: absence must not silently create a replacement pane.
    char tmux[] = "/usr/bin/tmux";
    char socket_option[] = "-L";
    char create[] = "new-session", attach[] = "attach-session";
    char session_option[] = "-s", target_option[] = "-t", session_name[] = "owner";
    char directory_option[] = "-c", directory[] = "/data/misc_ce/0/andrix", end_options[] = "--";
    char* socket_name = const_cast<char*>(command.socket_name.c_str());
    char* create_args[] = {tmux, socket_option, socket_name, create, session_option,
        session_name, directory_option, directory, end_options, executable, interactive, nullptr};
    char* attach_args[] = {tmux, socket_option, socket_name, attach, target_option, session_name, nullptr};
    dprintf(STDOUT_FILENO, "Andrix kept terminal: uid=%u; fresh tmux presentation\r\n", getuid());
    execve(tmux, command.mode == andrix::RunnerMode::TmuxNew ? create_args : attach_args, environment);
    fail("tmux execve");
  }
#endif
  dprintf(STDOUT_FILENO, "Andrix owner session: uid=%u; existing CE home; bounded native shell\r\n", getuid());
  execve(executable, arguments, environment);
  fail("shell execve");
}
