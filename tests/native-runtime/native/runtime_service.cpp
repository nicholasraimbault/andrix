// SPDX-License-Identifier: Apache-2.0
// Disposable characterization service for Android's existing native isolated
// service route. It reports the startup profile that route gives one service
// instance so it can be compared with the managed control. It is not a
// production launcher, principal integration or capability binding. It never
// exits, restarts, requests foreground state or changes policy or flags.
//
// Lifecycle. ANativeService_onCreate accepts the first instance in the process
// and installs onBind, onUnbind and onDestroy through the public setters. The
// accepted order is create, one bind, unbind with that bind token, destroy.
// Destroy is also accepted straight after create or bind. The bind action is
// the nonce and must match [A-Za-z0-9_]{1,64}. The bind data must be null.
// Anything else is refused without a state change: another instance, a second
// create or bind, a bad nonce, an unknown bind token or a callback after
// destroy. A refused bind returns null. onUnbind always returns false, so the
// framework never asks for onRebind. If CLOCK_BOOTTIME or the binder class is
// unavailable at create, that instance refuses every callback.
//
// Each accepted transition logs one INFO line with tag AndrixRuntime:
//   ANDRIX_RUNTIME {"version":1,"kind":"native","event":"bind","nonce":"n1",
//   "pid":1,"uid":2,"created_elapsed_ms":3,"elapsed_ms":4}
// The line is wrapped here only for width. The event is create, bind, unbind
// or destroy. The create record has an empty nonce. Later records carry the
// exact bound nonce, or an empty one when destroy follows create without a
// bind. Times are CLOCK_BOOTTIME milliseconds. Refused callbacks log nothing.
// An accepted unbind or destroy whose time cannot be read is not logged.
//
// Binder protocol. Descriptor dev.andrix.proof.nativeruntime.IProfile.
// Transaction code 1 is synchronous and has no fields after the interface
// token, which libbinder_ndk enforces before onTransact runs. Success replies
// with exactly one UTF-8 JSON string from AParcel_writeString and no status
// header. Otherwise the client receives only one of these statuses:
//   STATUS_UNKNOWN_TRANSACTION  any other user transaction code
//   STATUS_BAD_VALUE            data remains after the interface token
//   STATUS_INVALID_OPERATION    the instance is not currently bound
//   STATUS_FAILED_TRANSACTION   no calling pid, as in a oneway call, or any
//                               read, limit or format failure
// JSON fields, in order: version (1), kind ("native"), nonce, pid, uid, gid,
// caller_pid and caller_uid (binder calling identity), created_elapsed_ms,
// elapsed_ms, status (/proc/self/status), cgroup (/proc/self/cgroup), selinux
// (/proc/self/attr/current without trailing newline or NUL bytes), exe
// (readlink of /proc/self/exe) and art_present. Byte limits are 8192 for
// status and cgroup and 1024 for selinux and exe. Content over a limit or not
// valid UTF-8 fails the query; nothing is truncated, replaced or defaulted.
// art_present is true when an own mapping's path ends in /libart.so, deleted
// or not. The scan reads /proc/self/maps line by line, fails past 1 MiB and
// reports no mapping.
#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>
#include <android/log.h>
#include <android/native_service.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

namespace {

constexpr char kDescriptor[] = "dev.andrix.proof.nativeruntime.IProfile";
constexpr transaction_code_t kQueryProfile = 1;
constexpr char kLogTag[] = "AndrixRuntime";
constexpr int64_t kVersion = 1;

constexpr size_t kNonceMax = 64;
constexpr size_t kStatusMax = 8192;
constexpr size_t kCgroupMax = 8192;
constexpr size_t kSelinuxMax = 1024;
constexpr size_t kExeMax = 1024;
constexpr size_t kMapsMax = 1024 * 1024;
constexpr size_t kMapsLineMax = 8192;
constexpr size_t kMapsChunk = 16 * 1024;
// Escaping turns one control byte into at most six JSON bytes.
constexpr size_t kProfileMax =
    1024 + 6 * (kNonceMax + kStatusMax + kCgroupMax + kSelinuxMax + kExeMax);
constexpr size_t kRecordMax = 512;
constexpr char kHex[] = "0123456789abcdef";

enum class Phase { kNone, kCreated, kBound, kUnbound, kDestroyed, kFailed };

// Lifecycle callbacks run on the main thread and profile queries on binder
// threads. g_lock guards every field. Nobody holds it across file or log IO,
// so a lifecycle callback never waits on a client.
struct State {
  Phase phase;
  ANativeService* service;
  AIBinder_Class* clazz;
  AIBinder* binder;  // this library's own strong reference until destroy
  uint64_t bind_token;
  int64_t created_ms;
  size_t nonce_len;
  char nonce[kNonceMax + 1];
};

pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
State g_state;  // static zero initialization: kNone, no service, no binder

struct Snapshot {
  int64_t created_ms;
  size_t nonce_len;
  char nonce[kNonceMax + 1];
};

// Caller holds g_lock.
void take_snapshot(Snapshot* snapshot) {
  snapshot->created_ms = g_state.created_ms;
  snapshot->nonce_len = g_state.nonce_len;
  memcpy(snapshot->nonce, g_state.nonce, g_state.nonce_len);
  snapshot->nonce[g_state.nonce_len] = '\0';
}

bool boottime_ms(int64_t* out) {
  timespec now{};
  if (clock_gettime(CLOCK_BOOTTIME, &now) != 0 || now.tv_sec < 0 ||
      now.tv_nsec < 0) {
    return false;
  }
  *out = int64_t(now.tv_sec) * 1000 + int64_t(now.tv_nsec) / 1000000;
  return true;
}

bool nonce_char(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '_';
}

// Accepts exactly [A-Za-z0-9_]{1,64} and reads at most 65 bytes of action.
bool valid_nonce(const char* action, size_t* length) {
  if (action == nullptr) return false;
  size_t n = 0;
  while (action[n] != '\0') {
    if (n == kNonceMax || !nonce_char(action[n])) return false;
    ++n;
  }
  if (n == 0) return false;
  *length = n;
  return true;
}

// Bounded text output. Overflow or invalid input clears ok, and callers then
// refuse rather than emit a partial result.
struct Builder {
  char* data;
  size_t capacity;  // including the terminating NUL
  size_t length;
  bool ok;
};

void builder_init(Builder* out, char* data, size_t capacity) {
  out->data = data;
  out->capacity = capacity;
  out->length = 0;
  out->ok = capacity > 0;
  if (out->ok) data[0] = '\0';
}

void append_bytes(Builder* out, const char* bytes, size_t n) {
  if (!out->ok) return;
  if (n >= out->capacity - out->length) {
    out->ok = false;
    return;
  }
  memcpy(out->data + out->length, bytes, n);
  out->length += n;
  out->data[out->length] = '\0';
}

void append_text(Builder* out, const char* text) {
  append_bytes(out, text, strlen(text));
}

void append_i64(Builder* out, int64_t value) {
  char digits[24];
  const int n = snprintf(digits, sizeof(digits), "%" PRId64, value);
  if (n < 0 || size_t(n) >= sizeof(digits)) {
    out->ok = false;
    return;
  }
  append_bytes(out, digits, size_t(n));
}

void append_u64(Builder* out, uint64_t value) {
  char digits[24];
  const int n = snprintf(digits, sizeof(digits), "%" PRIu64, value);
  if (n < 0 || size_t(n) >= sizeof(digits)) {
    out->ok = false;
    return;
  }
  append_bytes(out, digits, size_t(n));
}

// Length of the well formed UTF-8 sequence starting at text[i], whose lead
// byte is 0x80 or more, or 0. Overlong forms, surrogates and code points
// above U+10FFFF are not well formed.
size_t utf8_sequence(const unsigned char* text, size_t n, size_t i) {
  const unsigned char lead = text[i];
  size_t tail = 0;
  unsigned char low = 0x80;
  unsigned char high = 0xbf;
  if (lead >= 0xc2 && lead <= 0xdf) {
    tail = 1;
  } else if (lead == 0xe0) {
    tail = 2;
    low = 0xa0;
  } else if (lead == 0xed) {
    tail = 2;
    high = 0x9f;
  } else if (lead >= 0xe1 && lead <= 0xef) {
    tail = 2;
  } else if (lead == 0xf0) {
    tail = 3;
    low = 0x90;
  } else if (lead >= 0xf1 && lead <= 0xf3) {
    tail = 3;
  } else if (lead == 0xf4) {
    tail = 3;
    high = 0x8f;
  } else {
    return 0;
  }
  if (n - i <= tail) return 0;
  if (text[i + 1] < low || text[i + 1] > high) return 0;
  for (size_t k = 2; k <= tail; ++k) {
    if (text[i + k] < 0x80 || text[i + k] > 0xbf) return 0;
  }
  return tail + 1;
}

// Appends text as a JSON string. Control bytes and DEL are escaped, well
// formed UTF-8 is kept as is, and anything else fails the builder.
void append_json_string(Builder* out, const char* text, size_t n) {
  const unsigned char* bytes = reinterpret_cast<const unsigned char*>(text);
  append_bytes(out, "\"", 1);
  size_t i = 0;
  while (out->ok && i < n) {
    const unsigned char c = bytes[i];
    if (c >= 0x80) {
      const size_t length = utf8_sequence(bytes, n, i);
      if (length == 0) {
        out->ok = false;
        return;
      }
      append_bytes(out, text + i, length);
      i += length;
      continue;
    }
    switch (c) {
      case '"':
        append_bytes(out, "\\\"", 2);
        break;
      case '\\':
        append_bytes(out, "\\\\", 2);
        break;
      case '\b':
        append_bytes(out, "\\b", 2);
        break;
      case '\f':
        append_bytes(out, "\\f", 2);
        break;
      case '\n':
        append_bytes(out, "\\n", 2);
        break;
      case '\r':
        append_bytes(out, "\\r", 2);
        break;
      case '\t':
        append_bytes(out, "\\t", 2);
        break;
      default:
        if (c < 0x20 || c == 0x7f) {
          const char escaped[6] = {'\\', 'u',          '0',
                                   '0',  kHex[c >> 4], kHex[c & 0xf]};
          append_bytes(out, escaped, sizeof(escaped));
        } else {
          append_bytes(out, text + i, 1);
        }
        break;
    }
    ++i;
  }
  append_bytes(out, "\"", 1);
}

// Reads a whole file of at most max bytes into buffer, which holds max + 1.
// A longer file fails rather than being truncated.
bool read_bounded_file(const char* path, char* buffer, size_t max,
                       size_t* length) {
  const int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  size_t n = 0;
  bool ok = true;
  for (;;) {
    const ssize_t got = read(fd, buffer + n, max + 1 - n);
    if (got < 0) {
      if (errno == EINTR) continue;
      ok = false;
      break;
    }
    if (got == 0) break;
    n += size_t(got);
    if (n > max) {
      ok = false;
      break;
    }
  }
  close(fd);
  if (ok) *length = n;
  return ok;
}

// readlink of /proc/self/exe. buffer holds max + 1 bytes so a longer target
// is detected rather than silently truncated.
bool read_exe(char* buffer, size_t max, size_t* length) {
  const ssize_t n = readlink("/proc/self/exe", buffer, max + 1);
  if (n <= 0 || size_t(n) > max) return false;
  *length = size_t(n);
  return true;
}

// A maps line is "start-end perms offset dev inode [path]". True only when
// path is absolute and its final component is exactly libart.so, with or
// without the kernel's " (deleted)" suffix.
bool maps_line_is_libart(const char* line, size_t n) {
  size_t i = 0;
  for (int field = 0; field < 5; ++field) {
    while (i < n && line[i] == ' ') ++i;
    if (i == n) return false;
    while (i < n && line[i] != ' ') ++i;
  }
  while (i < n && line[i] == ' ') ++i;
  const char* path = line + i;
  size_t path_len = n - i;
  constexpr char kDeleted[] = " (deleted)";
  constexpr size_t kDeletedLen = sizeof(kDeleted) - 1;
  if (path_len > kDeletedLen &&
      memcmp(path + path_len - kDeletedLen, kDeleted, kDeletedLen) == 0) {
    path_len -= kDeletedLen;
  }
  if (path_len == 0 || path[0] != '/') return false;
  size_t base = path_len;
  while (path[base - 1] != '/') --base;
  constexpr char kLibart[] = "libart.so";
  constexpr size_t kLibartLen = sizeof(kLibart) - 1;
  return path_len - base == kLibartLen &&
         memcmp(path + base, kLibart, kLibartLen) == 0;
}

enum class MapsScan { kFound, kAbsent, kFailed };

// Scans maps content from fd one line at a time. Only the answer leaves this
// function; no mapping text is kept or reported.
MapsScan scan_maps_for_libart(int fd, char* chunk, size_t chunk_size,
                              char* line, size_t line_max) {
  size_t total = 0;
  size_t line_len = 0;
  for (;;) {
    // Never read past the limit. At the limit a one byte probe tells the end
    // of the file apart from content over the limit.
    size_t want = kMapsMax - total;
    if (want > chunk_size) want = chunk_size;
    if (want == 0) want = 1;
    const ssize_t got = read(fd, chunk, want);
    if (got < 0) {
      if (errno == EINTR) continue;
      return MapsScan::kFailed;
    }
    if (got == 0) {
      // The last line may lack a newline.
      return line_len > 0 && maps_line_is_libart(line, line_len)
                 ? MapsScan::kFound
                 : MapsScan::kAbsent;
    }
    if (size_t(got) > kMapsMax - total) return MapsScan::kFailed;
    total += size_t(got);
    for (size_t i = 0; i < size_t(got); ++i) {
      if (chunk[i] == '\n') {
        if (maps_line_is_libart(line, line_len)) return MapsScan::kFound;
        line_len = 0;
      } else if (line_len == line_max) {
        return MapsScan::kFailed;
      } else {
        line[line_len++] = chunk[i];
      }
    }
  }
}

void emit_record(const char* event, const Snapshot& snapshot,
                 int64_t elapsed_ms) {
  char text[kRecordMax];
  Builder record;
  builder_init(&record, text, sizeof(text));
  append_text(&record, "{\"version\":");
  append_i64(&record, kVersion);
  append_text(&record, ",\"kind\":\"native\",\"event\":");
  append_json_string(&record, event, strlen(event));
  append_text(&record, ",\"nonce\":");
  append_json_string(&record, snapshot.nonce, snapshot.nonce_len);
  append_text(&record, ",\"pid\":");
  append_i64(&record, getpid());
  append_text(&record, ",\"uid\":");
  append_u64(&record, getuid());
  append_text(&record, ",\"created_elapsed_ms\":");
  append_i64(&record, snapshot.created_ms);
  append_text(&record, ",\"elapsed_ms\":");
  append_i64(&record, elapsed_ms);
  append_text(&record, "}");
  if (!record.ok) return;  // cannot happen within kRecordMax; never partial
  __android_log_print(ANDROID_LOG_INFO, kLogTag, "ANDRIX_RUNTIME %s",
                      record.data);
}

struct ProfileScratch {
  char status[kStatusMax + 1];
  char cgroup[kCgroupMax + 1];
  char selinux[kSelinuxMax + 1];
  char exe[kExeMax + 1];
  char maps_chunk[kMapsChunk];
  char maps_line[kMapsLineMax];
  char json[kProfileMax];
};

binder_status_t write_profile(ProfileScratch* scratch,
                              const Snapshot& snapshot, pid_t caller_pid,
                              uid_t caller_uid, int64_t elapsed_ms,
                              AParcel* out) {
  size_t status_len = 0;
  size_t cgroup_len = 0;
  size_t selinux_len = 0;
  size_t exe_len = 0;
  if (!read_bounded_file("/proc/self/status", scratch->status, kStatusMax,
                         &status_len) ||
      !read_bounded_file("/proc/self/cgroup", scratch->cgroup, kCgroupMax,
                         &cgroup_len) ||
      !read_bounded_file("/proc/self/attr/current", scratch->selinux,
                         kSelinuxMax, &selinux_len) ||
      !read_exe(scratch->exe, kExeMax, &exe_len)) {
    return STATUS_FAILED_TRANSACTION;
  }
  while (selinux_len > 0 && (scratch->selinux[selinux_len - 1] == '\n' ||
                             scratch->selinux[selinux_len - 1] == '\0')) {
    --selinux_len;
  }
  const int maps = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  if (maps < 0) return STATUS_FAILED_TRANSACTION;
  const MapsScan art = scan_maps_for_libart(
      maps, scratch->maps_chunk, sizeof(scratch->maps_chunk),
      scratch->maps_line, sizeof(scratch->maps_line));
  close(maps);
  if (art == MapsScan::kFailed) return STATUS_FAILED_TRANSACTION;

  Builder json;
  builder_init(&json, scratch->json, sizeof(scratch->json));
  append_text(&json, "{\"version\":");
  append_i64(&json, kVersion);
  append_text(&json, ",\"kind\":\"native\",\"nonce\":");
  append_json_string(&json, snapshot.nonce, snapshot.nonce_len);
  append_text(&json, ",\"pid\":");
  append_i64(&json, getpid());
  append_text(&json, ",\"uid\":");
  append_u64(&json, getuid());
  append_text(&json, ",\"gid\":");
  append_u64(&json, getgid());
  append_text(&json, ",\"caller_pid\":");
  append_i64(&json, caller_pid);
  append_text(&json, ",\"caller_uid\":");
  append_u64(&json, caller_uid);
  append_text(&json, ",\"created_elapsed_ms\":");
  append_i64(&json, snapshot.created_ms);
  append_text(&json, ",\"elapsed_ms\":");
  append_i64(&json, elapsed_ms);
  append_text(&json, ",\"status\":");
  append_json_string(&json, scratch->status, status_len);
  append_text(&json, ",\"cgroup\":");
  append_json_string(&json, scratch->cgroup, cgroup_len);
  append_text(&json, ",\"selinux\":");
  append_json_string(&json, scratch->selinux, selinux_len);
  append_text(&json, ",\"exe\":");
  append_json_string(&json, scratch->exe, exe_len);
  append_text(&json, ",\"art_present\":");
  append_text(&json, art == MapsScan::kFound ? "true" : "false");
  append_text(&json, "}");
  if (!json.ok || json.length > size_t(INT32_MAX)) {
    return STATUS_FAILED_TRANSACTION;
  }
  if (AParcel_writeString(out, json.data, int32_t(json.length)) !=
      STATUS_OK) {
    return STATUS_FAILED_TRANSACTION;
  }
  return STATUS_OK;
}

binder_status_t query_profile(AIBinder* binder, const AParcel* in,
                              AParcel* out) {
  // The request is the interface token alone. The public position and size
  // show whether anything follows it.
  const int32_t position = AParcel_getDataPosition(in);
  if (position < 0 || position != AParcel_getDataSize(in)) {
    return STATUS_BAD_VALUE;
  }
  // A oneway call has no calling pid. Refuse rather than report zero.
  const pid_t caller_pid = AIBinder_getCallingPid();
  const uid_t caller_uid = AIBinder_getCallingUid();
  if (caller_pid <= 0) return STATUS_FAILED_TRANSACTION;

  Snapshot snapshot{};
  pthread_mutex_lock(&g_lock);
  const bool bound = g_state.phase == Phase::kBound && g_state.binder == binder;
  if (bound) take_snapshot(&snapshot);
  pthread_mutex_unlock(&g_lock);
  if (!bound) return STATUS_INVALID_OPERATION;

  int64_t elapsed_ms = 0;
  if (!boottime_ms(&elapsed_ms)) return STATUS_FAILED_TRANSACTION;
  auto* scratch = static_cast<ProfileScratch*>(malloc(sizeof(ProfileScratch)));
  if (scratch == nullptr) return STATUS_FAILED_TRANSACTION;
  const binder_status_t result = write_profile(scratch, snapshot, caller_pid,
                                               caller_uid, elapsed_ms, out);
  free(scratch);
  return result;
}

void* on_binder_create(void* args) {
  return args;  // stateless; each query reads the profile afresh
}

void on_binder_destroy(void* /* user_data */) {}

binder_status_t on_transact(AIBinder* binder, transaction_code_t code,
                            const AParcel* in, AParcel* out) {
  if (code != kQueryProfile) return STATUS_UNKNOWN_TRANSACTION;
  if (binder == nullptr || in == nullptr || out == nullptr) {
    return STATUS_FAILED_TRANSACTION;
  }
  return query_profile(binder, in, out);
}

AIBinder* on_bind(ANativeService* service, uint64_t bind_token,
                  const char* action, const char* data) {
  size_t nonce_len = 0;
  int64_t elapsed_ms = 0;
  if (data != nullptr || !valid_nonce(action, &nonce_len) ||
      !boottime_ms(&elapsed_ms)) {
    return nullptr;
  }
  pthread_mutex_lock(&g_lock);
  if (service == nullptr || service != g_state.service ||
      g_state.phase != Phase::kCreated) {
    pthread_mutex_unlock(&g_lock);
    return nullptr;
  }
  AIBinder* binder = AIBinder_new(g_state.clazz, nullptr);
  if (binder == nullptr) {
    pthread_mutex_unlock(&g_lock);
    return nullptr;
  }
  // AIBinder_new gave this library one strong reference, kept until destroy.
  // The added reference is the one onBind transfers to the framework.
  AIBinder_incStrong(binder);
  g_state.binder = binder;
  g_state.bind_token = bind_token;
  memcpy(g_state.nonce, action, nonce_len);
  g_state.nonce[nonce_len] = '\0';
  g_state.nonce_len = nonce_len;
  g_state.phase = Phase::kBound;
  Snapshot snapshot{};
  take_snapshot(&snapshot);
  pthread_mutex_unlock(&g_lock);
  emit_record("bind", snapshot, elapsed_ms);
  return binder;
}

bool on_unbind(ANativeService* service, uint64_t bind_token) {
  int64_t elapsed_ms = 0;
  const bool clock_ok = boottime_ms(&elapsed_ms);
  Snapshot snapshot{};
  pthread_mutex_lock(&g_lock);
  const bool accepted = service != nullptr && service == g_state.service &&
                        g_state.phase == Phase::kBound &&
                        bind_token == g_state.bind_token;
  if (accepted) {
    g_state.phase = Phase::kUnbound;
    take_snapshot(&snapshot);
  }
  pthread_mutex_unlock(&g_lock);
  if (accepted && clock_ok) emit_record("unbind", snapshot, elapsed_ms);
  return false;
}

void on_destroy(ANativeService* service) {
  int64_t elapsed_ms = 0;
  const bool clock_ok = boottime_ms(&elapsed_ms);
  Snapshot snapshot{};
  AIBinder* held = nullptr;
  pthread_mutex_lock(&g_lock);
  const bool accepted =
      service != nullptr && service == g_state.service &&
      (g_state.phase == Phase::kCreated || g_state.phase == Phase::kBound ||
       g_state.phase == Phase::kUnbound);
  if (accepted) {
    g_state.phase = Phase::kDestroyed;
    g_state.service = nullptr;
    held = g_state.binder;
    g_state.binder = nullptr;
    take_snapshot(&snapshot);
  }
  pthread_mutex_unlock(&g_lock);
  if (accepted && clock_ok) emit_record("destroy", snapshot, elapsed_ms);
  if (held != nullptr) AIBinder_decStrong(held);
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void ANativeService_onCreate(
    ANativeService* service) {
  if (service == nullptr) return;
  // Every instance gets these callbacks, refused ones included, so each later
  // outcome is decided here rather than by a framework default.
  ANativeService_setOnBindCallback(service, on_bind);
  ANativeService_setOnUnbindCallback(service, on_unbind);
  ANativeService_setOnDestroyCallback(service, on_destroy);

  int64_t created_ms = 0;
  const bool clock_ok = boottime_ms(&created_ms);
  pthread_mutex_lock(&g_lock);
  if (g_state.phase != Phase::kNone) {
    pthread_mutex_unlock(&g_lock);
    return;  // one instance per process
  }
  g_state.service = service;
  g_state.clazz = clock_ok ? AIBinder_Class_define(kDescriptor,
                                                   on_binder_create,
                                                   on_binder_destroy,
                                                   on_transact)
                           : nullptr;
  if (g_state.clazz == nullptr) {
    g_state.phase = Phase::kFailed;
    pthread_mutex_unlock(&g_lock);
    return;
  }
  g_state.created_ms = created_ms;
  g_state.phase = Phase::kCreated;
  Snapshot snapshot{};
  take_snapshot(&snapshot);
  pthread_mutex_unlock(&g_lock);
  emit_record("create", snapshot, created_ms);
}
