// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <android-base/unique_fd.h>
#include <sys/types.h>

#include <cstdint>
#include <string>

#include "wire.h"

namespace andrix::factory_proof {
uint64_t now_ms();
uint64_t random_id();
bool parse_id(const char* text, uint64_t* out);
std::string read_small(const std::string& path);
std::string role();
std::string current_group();
std::string bounds_error(const std::string& group, bool worker);
bool populated(int directory);
bool write_control(int directory, const char* name, const std::string& value);
android::base::unique_fd open_group(const std::string& group);
void labelled_channel(int pair[2]);
android::base::unique_fd manager_socket(uint64_t manager, bool listener);
bool peer_is_coordinator(int fd, pid_t* pid);
bool send_packet(int fd, const Packet& packet);
bool receive_packet(int fd, Packet* packet);
[[noreturn]] void fail(const std::string& message);
}  // namespace andrix::factory_proof
