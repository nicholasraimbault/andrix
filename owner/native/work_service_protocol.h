// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "work_catalog.h"
#include "work_runtime_state.h"

namespace andrix {
// Internal operation schema over the separately authenticated packet channel.
// Every request after Hello names the exact enclosing service incarnation.
struct WorkServiceIdentity {
  uint64_t boot = 0, environment = 0, manager = 0;
  bool operator==(const WorkServiceIdentity&) const = default;
};
enum class WorkServiceOperation : uint32_t {
  Hello = 1,
  OpenStream,
  CloseStream,
  Reserve,
  Bind,
  Inspect,
  Prepare,
  Start,
  Stop,
  Forget,
  List,
  LookupRequest
};
// Volatile request identity, not a bearer capability or durable receipt.
// Kept separately from a work reference so a lost Reserve reply is queryable.
struct WorkRequestReference {
  WorkServiceIdentity service;
  uint64_t stream = 0, sequence = 0;
  bool operator==(const WorkRequestReference&) const = default;
};
std::string FormatWorkRequestReference(const WorkRequestReference& reference);
std::optional<WorkRequestReference> ParseWorkRequestReference(
    std::string_view text);

struct WorkServiceRequest {
  WorkServiceIdentity service;
  uint64_t stream = 0, sequence = 0, serial = 0, input = 0;
  uint32_t stdio_closed = 0;
};
struct WorkServiceReport {
  WorkCatalogSnapshot catalog;
  WorkRuntimeSnapshot runtime;
};
struct WorkServiceReply {
  WorkServiceIdentity service;
  WorkRegistryResult result = WorkRegistryResult::Invalid;
  int error = 0;
  uint64_t stream = 0, serial = 0, input = 0;
  std::vector<WorkServiceReport> works;
};
constexpr size_t kWorkServiceRequestBytes = 64;
constexpr size_t kWorkServiceMaximumReports = WorkRegistry::kMaximumRecords;
std::vector<uint8_t> EncodeWorkServiceRequest(
    const WorkServiceRequest& request);
bool DecodeWorkServiceRequest(std::span<const uint8_t> bytes,
                              WorkServiceRequest& request);
// These validate operation-specific fields, not principal authorization.
bool ValidWorkServiceRequest(WorkServiceOperation operation,
                             const WorkServiceRequest& request,
                             size_t descriptors);
std::vector<uint8_t> EncodeWorkServiceReply(const WorkServiceReply& reply);
bool DecodeWorkServiceReply(std::span<const uint8_t> bytes,
                            WorkServiceReply& reply);
}  // namespace andrix
