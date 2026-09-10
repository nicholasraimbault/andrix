// SPDX-License-Identifier: Apache-2.0
#include "terminal_protocol.h"
#include <sys/socket.h>
#include <unistd.h>
#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <random>
#include <string>

using namespace andrix::terminal;

static std::string receive(int fd, size_t count) {
  std::string result;
  while (result.size() < count) {
    char byte;
    assert(read(fd, &byte, 1) == 1);
    result.push_back(byte);
  }
  return result;
}

static void headers() {
  std::array<char, kHeaderSize> raw{};
  Header decoded{};
  assert(encode_header({3, 0x0102030405060708, 0x1011121314151617}, &raw));
  assert(std::string_view(raw.data(), 4) == "ATX1");
  assert(static_cast<unsigned char>(raw[7]) == 3 && raw[8] == 1 && raw[15] == 8);
  assert(decode_header({raw.data(), raw.size()}, &decoded));
  assert(decoded.length == 3 && decoded.session == 0x0102030405060708 &&
         decoded.offset == 0x1011121314151617);
  assert(!decode_header({raw.data(), 23}, &decoded));
  raw[0] = 'B';
  assert(!decode_header({raw.data(), raw.size()}, &decoded));
  for (Header bad : {Header{0, 1, 0}, Header{4097, 1, 0}, Header{1, 0, 0},
                     Header{1, uint64_t{1} << 63, 0}, Header{1, 1, kMaximumOffset}})
    assert(!encode_header(bad, &raw));
  assert(encode_frame(1, 0, "").empty());
  assert(encode_frame(1, 0, std::string(4097, 'x')).empty());
  assert(!encode_header({1, 1, 0}, nullptr));
  assert(!decode_header("", nullptr));
  assert(encode_header({1, kMaximumOffset, kMaximumOffset - 1}, &raw));
  assert(decode_header({raw.data(), raw.size()}, &decoded));
  raw[4] = raw[5] = raw[6] = raw[7] = static_cast<char>(0xff);
  assert(!decode_header({raw.data(), raw.size()}, &decoded));
  std::mt19937 random(42);
  for (int i = 0; i < 10000; ++i) {
    for (char& c : raw) c = static_cast<char>(random());
    assert(!decode_header({raw.data(), raw.size()}, &decoded));
  }
}

static void journal() {
  OutputJournal log(8);
  assert(log.append("abc"));
  assert(log.size() == 3 && log.begin() == 0 && log.end() == 3);
  assert(!log.acknowledge(1)); // merely queued, not delivered
  assert(!log.delivered(4));
  assert(log.delivered(3));
  assert(log.size() == 3); // send is NOT an acknowledgement
  assert(log.acknowledge(2));
  assert(log.begin() == 2 && log.end() == 3 && log.size() == 1);
  assert(log.acknowledge(1) && log.begin() == 2); // stale ack cannot rewind
  assert(log.append("defghijk"));
  assert(log.begin() == 3 && log.end() == 11 && log.dropped() == 1);
  auto r = log.read(2);
  assert(r.valid && r.gap && r.offset == 3 && r.bytes == "defghijk");
  assert(!log.acknowledge(11)); // retained newer output not delivered
  assert(log.delivered(11) && log.acknowledge(11));
  assert(log.size() == 0 && log.begin() == 11 && log.acknowledged() == 11);
  assert(log.delivered(3) && log.delivered_end() == 11); // replay high-water mark
  assert(log.append("lm"));
  assert(log.read(11).bytes == "lm" && !log.read(11).gap);
  assert(!log.read(14).valid && !log.read(11, 0).valid && !log.read(11, 4097).valid);
  assert(log.read(13).valid && log.read(13).bytes.empty());

  OutputJournal limited(4, 5);
  assert(limited.append("12345"));
  assert(limited.begin() == 1 && limited.end() == 5 && limited.size() == 4);
  assert(!limited.append("6"));
  assert(limited.begin() == 1 && limited.end() == 5 && limited.read(1).bytes == "2345");
  assert(limited.append(""));
  OutputJournal zero(0);
  assert(zero.append("abc") && zero.read(0).gap && zero.read(0).bytes.empty());
  assert(zero.dropped() == 3 && zero.delivered(3) && zero.acknowledge(3));
  OutputJournal maximum(kJournalLimit * 2);
  assert(maximum.append(std::string(kJournalLimit + 1, 'x')));
  assert(maximum.size() == kJournalLimit && maximum.dropped() == 1);
  assert(maximum.read(1).bytes.size() == kFramePayloadLimit);
}

static void socket_replay() {
  OutputJournal log;
  assert(log.append("\033[31mhello\xc3\xa9\033[0m"));
  auto r = log.read(0);
  const std::string frame = encode_frame(7, r.offset, r.bytes);
  int pair[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
  // A connection dies after only part of a header. There is nothing to ack.
  assert(write(pair[0], frame.data(), 5) == 5);
  assert(receive(pair[1], 5) == frame.substr(0, 5));
  close(pair[0]);
  char byte;
  assert(read(pair[1], &byte, 1) == 0);
  close(pair[1]);
  assert(!log.acknowledge(r.bytes.size()));
  assert(log.read(0).bytes == r.bytes);

  for (int attempt = 0; attempt < 2; ++attempt) {
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    // Exercise a real fragmented byte stream, not assumed message boundaries.
    for (char c : frame) assert(write(pair[0], &c, 1) == 1);
    assert(log.delivered(r.bytes.size()));
    assert(receive(pair[1], frame.size()) == frame);
    close(pair[0]); close(pair[1]);
    assert(log.size() == r.bytes.size()); // lost ack is replayed, not discarded
  }
  assert(log.acknowledge(r.bytes.size()));
  assert(log.read(r.bytes.size()).bytes.empty());
}

int main(int argc, char** argv) {
  if (argc == 2 && std::strcmp(argv[1], "--fixture") == 0) {
    const auto frame = encode_frame(74565, 3, "\033[31m\xce\xbb");
    std::cout.write(frame.data(), frame.size());
    return 0;
  }
  assert(argc == 1);
  headers(); journal(); socket_replay();
  std::cout << "PASS: journal/framing/replay with real host sockets; Android transport not yet integrated\n";
}
