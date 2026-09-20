// SPDX-License-Identifier: Apache-2.0
#include "work_service_protocol.h"

#include <bit>
#include <charconv>
#include <climits>
#include <iterator>
#include <limits>
#include <utility>

namespace andrix {
namespace {
void u32(std::vector<uint8_t>& out, uint32_t value) {
  for (unsigned n = 0; n < 4; ++n) out.push_back(value >> (8 * n));
}
void u64(std::vector<uint8_t>& out, uint64_t value) {
  for (unsigned n = 0; n < 8; ++n) out.push_back(value >> (8 * n));
}
struct Reader {
  std::span<const uint8_t> bytes;
  bool good = true;
  uint64_t number(size_t size) {
    if (bytes.size() < size) {
      good = false;
      return 0;
    }
    uint64_t value = 0;
    for (size_t n = 0; n < size; ++n) value |= uint64_t(bytes[n]) << (8 * n);
    bytes = bytes.subspan(size);
    return value;
  }
  uint32_t word() { return static_cast<uint32_t>(number(4)); }
  uint64_t wide() { return number(8); }
};
void identity(std::vector<uint8_t>& out, WorkServiceIdentity value) {
  u64(out, value.boot);
  u64(out, value.environment);
  u64(out, value.manager);
}
WorkServiceIdentity identity(Reader& input) {
  return {input.wide(), input.wide(), input.wide()};
}
bool valid(WorkServiceIdentity value) {
  return value.boot && value.environment && value.manager;
}
void report(std::vector<uint8_t>& out, const WorkServiceReport& value) {
  const auto& work = value.catalog.work;
  u64(out, work.work.manager);
  u64(out, work.work.serial);
  u64(out, work.stream);
  u64(out, work.request_sequence);
  uint32_t flags =
      uint32_t(work.start_accepted) | (uint32_t(work.admission_pending) << 1) |
      (uint32_t(work.creator_pending) << 2) |
      (uint32_t(work.entry_claimed) << 3) |
      (uint32_t(work.entry_gate_closed) << 4) |
      (uint32_t(work.observation_pending) << 5) |
      (uint32_t(work.cleanup_pending) << 6) | (uint32_t(work.blocked) << 7) |
      (uint32_t(work.complete) << 8) | (uint32_t(work.forgotten) << 9) |
      (uint32_t(work.stdio_configured) << 10) |
      (uint32_t(work.stdio_closed_plan) << 11) |
      (uint32_t(work.epoch.has_value()) << 12);
  u32(out, flags);
  u32(out, work.stop_sources);
  u32(out, static_cast<uint32_t>(work.admission));
  u32(out, static_cast<uint32_t>(work.initial));
  u32(out, static_cast<uint32_t>(work.initial_exit.kind));
  u32(out, work.initial_exit.value);
  u32(out, static_cast<uint32_t>(work.scope));
  u32(out, static_cast<uint32_t>(work.population));
  u32(out, static_cast<uint32_t>(work.fault));
  u32(out, work.launch_error);
  u32(out, work.cleanup_error);
  auto epoch = work.epoch.value_or(AuthorityEpoch{});
  u32(out, static_cast<uint32_t>(epoch.user));
  u64(out, epoch.platform);
  u64(out, epoch.generation);
  u64(out, work.scope_identity.device);
  u64(out, work.scope_identity.inode);
  u64(out, work.stdio.manager);
  u64(out, work.stdio.serial);
  u32(out, static_cast<uint32_t>(value.catalog.inputs));
  u32(out, value.catalog.input_error);
  u64(out, value.catalog.input.manager);
  u64(out, value.catalog.input.serial);
  u32(out, static_cast<uint32_t>(value.runtime.phase));
  u32(out, uint32_t(value.runtime.kill_pending) |
               (uint32_t(value.runtime.blocked) << 1) |
               (uint32_t(value.runtime.lifecycle_ceased) << 2));
  u32(out, value.runtime.error);
  u32(out, value.runtime.kill_error);
  u32(out, value.runtime.initial_pid);
  u32(out, 0);
}
bool report(Reader& in, WorkServiceIdentity service, WorkServiceReport& value) {
  auto& work = value.catalog.work;
  work.work = {in.wide(), in.wide()};
  work.stream = in.wide();
  work.request_sequence = in.wide();
  const auto flags = in.word(), stops = in.word(), admission = in.word(),
             initial = in.word(), exit_kind = in.word(), exit_value = in.word();
  const auto scope = in.word(), population = in.word(), fault = in.word(),
             launch_error = in.word(), cleanup_error = in.word(),
             user = in.word();
  const auto platform = in.wide(), generation = in.wide();
  work.scope_identity = {in.wide(), in.wide()};
  work.stdio = {in.wide(), in.wide()};
  const auto inputs = in.word(), input_error = in.word();
  value.catalog.input = {in.wide(), in.wide()};
  const auto runtime = in.word(), runtime_flags = in.word(),
             runtime_error = in.word(), kill_error = in.word(), pid = in.word(),
             reserved = in.word();
  if (!in.good || work.work.manager != service.manager || !work.work.serial ||
      flags & ~0x1fffU || stops & ~15U ||
      admission > static_cast<uint32_t>(AdmissionResult::Invalid) ||
      initial > static_cast<uint32_t>(WorkInitialState::Reaped) ||
      exit_kind > static_cast<uint32_t>(WorkExitKind::Signal) ||
      scope > static_cast<uint32_t>(WorkScopeState::Reclaimed) ||
      population > static_cast<uint32_t>(WorkPopulation::Empty) ||
      fault > static_cast<uint32_t>(WorkRegistryFault::InvalidAdmission) ||
      inputs > static_cast<uint32_t>(WorkInputState::Rejected) ||
      runtime > static_cast<uint32_t>(WorkRuntimePhase::Blocked) ||
      runtime_flags & ~7U || reserved || launch_error > INT_MAX ||
      cleanup_error > INT_MAX || input_error > INT_MAX ||
      runtime_error > INT_MAX || kill_error > INT_MAX || pid > INT_MAX ||
      (exit_kind == 0   ? exit_value != 0
       : exit_kind == 1 ? exit_value > 255
                        : !exit_value || exit_value > 64))
    return false;
  if (flags & (1U << 12)) {
    if (!platform || !generation || user > INT_MAX) return false;
    work.epoch =
        AuthorityEpoch{platform, generation, static_cast<int32_t>(user)};
  } else if (platform || generation || user != UINT32_MAX)
    return false;
  work.start_accepted = flags & 1;
  work.admission_pending = flags & 2;
  work.creator_pending = flags & 4;
  work.entry_claimed = flags & 8;
  work.entry_gate_closed = flags & 16;
  work.observation_pending = flags & 32;
  work.cleanup_pending = flags & 64;
  work.blocked = flags & 128;
  work.complete = flags & 256;
  work.forgotten = flags & 512;
  work.stdio_configured = flags & 1024;
  work.stdio_closed_plan = flags & 2048;
  work.stop_sources = stops;
  work.admission = static_cast<AdmissionResult>(admission);
  work.initial = static_cast<WorkInitialState>(initial);
  work.initial_exit = {static_cast<WorkExitKind>(exit_kind),
                       static_cast<int>(exit_value)};
  work.scope = static_cast<WorkScopeState>(scope);
  work.population = static_cast<WorkPopulation>(population);
  work.fault = static_cast<WorkRegistryFault>(fault);
  work.launch_error = launch_error;
  work.cleanup_error = cleanup_error;
  value.catalog.inputs = static_cast<WorkInputState>(inputs);
  value.catalog.input_error = input_error;
  value.runtime = {work.work,
                   static_cast<WorkRuntimePhase>(runtime),
                   bool(runtime_flags & 1),
                   bool(runtime_flags & 2),
                   bool(runtime_flags & 4),
                   static_cast<int>(runtime_error),
                   static_cast<int>(kill_error),
                   static_cast<pid_t>(pid)};
  return true;
}
}  // namespace
std::string FormatWorkRequestReference(const WorkRequestReference& reference) {
  if (!valid(reference.service) || !reference.stream || !reference.sequence)
    return {};
  return std::to_string(reference.service.boot) + "." +
         std::to_string(reference.service.environment) + "." +
         std::to_string(reference.service.manager) + "." +
         std::to_string(reference.stream) + "." +
         std::to_string(reference.sequence);
}
std::optional<WorkRequestReference> ParseWorkRequestReference(
    std::string_view text) {
  WorkRequestReference value;
  uint64_t* fields[] = {&value.service.boot, &value.service.environment,
                        &value.service.manager, &value.stream, &value.sequence};
  for (size_t n = 0; n < std::size(fields); ++n) {
    auto dot = text.find('.');
    if ((n == std::size(fields) - 1) != (dot == text.npos)) return {};
    auto part = text.substr(0, dot);
    if (part.empty() || part.size() > 20) return {};
    auto parsed =
        std::from_chars(part.data(), part.data() + part.size(), *fields[n]);
    if (parsed.ec != std::errc{} || parsed.ptr != part.data() + part.size() ||
        !*fields[n])
      return {};
    if (dot != text.npos) text.remove_prefix(dot + 1);
  }
  return value;
}
std::vector<uint8_t> EncodeWorkServiceRequest(
    const WorkServiceRequest& request) {
  std::vector<uint8_t> bytes;
  bytes.reserve(kWorkServiceRequestBytes);
  identity(bytes, request.service);
  u64(bytes, request.stream);
  u64(bytes, request.sequence);
  u64(bytes, request.serial);
  u64(bytes, request.input);
  u32(bytes, request.stdio_closed);
  u32(bytes, 0);
  return bytes;
}
bool DecodeWorkServiceRequest(std::span<const uint8_t> bytes,
                              WorkServiceRequest& request) {
  if (bytes.size() != kWorkServiceRequestBytes) return false;
  Reader input{bytes};
  WorkServiceRequest value;
  value.service = identity(input);
  value.stream = input.wide();
  value.sequence = input.wide();
  value.serial = input.wide();
  value.input = input.wide();
  value.stdio_closed = input.word();
  if (input.word() || !input.good || !input.bytes.empty()) return false;
  request = value;
  return true;
}
bool ValidWorkServiceRequest(WorkServiceOperation operation,
                             const WorkServiceRequest& request,
                             size_t descriptors) {
  if (operation == WorkServiceOperation::Hello)
    return request.service == WorkServiceIdentity{} && !request.stream &&
           !request.sequence && !request.serial && !request.input &&
           !request.stdio_closed && !descriptors;
  if (!valid(request.service)) return false;
  if (operation == WorkServiceOperation::Prepare) {
    return request.serial && !request.stream && !request.sequence &&
           !request.input && !(request.stdio_closed & ~7U) &&
           descriptors == size_t{4} - static_cast<size_t>(
                                          std::popcount(request.stdio_closed));
  }
  if (descriptors || request.stdio_closed) return false;
  switch (operation) {
    case WorkServiceOperation::OpenStream:
    case WorkServiceOperation::List:
      return !request.stream && !request.sequence && !request.serial &&
             !request.input;
    case WorkServiceOperation::CloseStream:
      return request.stream && !request.sequence && !request.serial &&
             !request.input;
    case WorkServiceOperation::Reserve:
    case WorkServiceOperation::LookupRequest:
      return request.stream && request.sequence && !request.serial &&
             !request.input;
    case WorkServiceOperation::Start:
      return request.serial && request.input && !request.stream &&
             !request.sequence;
    case WorkServiceOperation::Bind:
    case WorkServiceOperation::Inspect:
    case WorkServiceOperation::Stop:
    case WorkServiceOperation::Forget:
      return request.serial && !request.input && !request.stream &&
             !request.sequence;
    default:
      return false;
  }
}
std::vector<uint8_t> EncodeWorkServiceReply(const WorkServiceReply& reply) {
  if (!valid(reply.service) || reply.error < 0 ||
      reply.works.size() > kWorkServiceMaximumReports)
    return {};
  std::vector<uint8_t> bytes;
  identity(bytes, reply.service);
  u32(bytes, static_cast<uint32_t>(reply.result));
  u32(bytes, reply.error);
  u64(bytes, reply.stream);
  u64(bytes, reply.serial);
  u64(bytes, reply.input);
  u32(bytes, reply.works.size());
  u32(bytes, 0);
  for (const auto& value : reply.works) report(bytes, value);
  return bytes;
}
bool DecodeWorkServiceReply(std::span<const uint8_t> bytes,
                            WorkServiceReply& reply) {
  Reader in{bytes};
  WorkServiceReply value;
  value.service = identity(in);
  auto result = in.word(), error = in.word();
  value.stream = in.wide();
  value.serial = in.wide();
  value.input = in.wide();
  auto count = in.word();
  auto reserved = in.word();
  if (!in.good || !valid(value.service) || reserved ||
      result > static_cast<uint32_t>(WorkRegistryResult::NotFound) ||
      error > INT_MAX || count > kWorkServiceMaximumReports)
    return false;
  value.result = static_cast<WorkRegistryResult>(result);
  value.error = error;
  value.works.resize(count);
  for (auto& item : value.works)
    if (!report(in, value.service, item)) return false;
  if (!in.good || !in.bytes.empty()) return false;
  reply = std::move(value);
  return true;
}
}  // namespace andrix
