// SPDX-License-Identifier: Apache-2.0
// Real shared LMKD packing and send functions. No daemon or privileged control.
#include <liblmkd_utils.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>

static_assert(LMK_TARGET == 0 && LMK_PROCPRIO == 1 && LMK_PROCREMOVE == 2 && LMK_PROCS_PRIO == 11);
static_assert(CTRL_PACKET_MAX_SIZE >= 8 * sizeof(int));
int main() {
    const lmk_service_instance value{123, 7500, 700, std::numeric_limits<uint64_t>::max(),
                                     0x123456789abcdef0ULL};
    LMKD_CTRL_PACKET packet{};
    assert(lmkd_pack_set_service_instance(packet, &value) == 8 * sizeof(int));
    assert(lmkd_pack_get_cmd(packet) == LMK_SERVICE_INSTANCE);
    lmk_service_instance parsed{};
    lmkd_pack_get_service_instance(packet, &parsed);
    assert(parsed.pid == value.pid && parsed.uid == value.uid && parsed.oomadj == value.oomadj &&
           parsed.boot == value.boot && parsed.instance == value.instance);
    assert(lmkd_pack_set_service_remove(packet, value.pid, value.boot, value.instance) ==
           6 * sizeof(int));
    assert(lmkd_pack_get_cmd(packet) == LMK_SERVICE_REMOVE);
    assert(lmkd_unpack_u64(packet, 2) == value.boot &&
           lmkd_unpack_u64(packet, 4) == value.instance);

    int sockets[2];
    assert(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets));
    int source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(source >= 0);
    assert(lmkd_register_service_instance(sockets[0], &value, source, source) == 0);
    alignas(cmsghdr) char control[CMSG_SPACE(2 * sizeof(int))]{};
    iovec bytes{packet, sizeof(packet)};
    msghdr message{};
    message.msg_iov = &bytes;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    assert(recvmsg(sockets[1], &message, MSG_CMSG_CLOEXEC) ==
           8 * static_cast<ssize_t>(sizeof(int)));
    assert(!(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) &&
           lmkd_pack_get_cmd(packet) == LMK_SERVICE_INSTANCE);
    auto* header = CMSG_FIRSTHDR(&message);
    assert(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
           header->cmsg_len == CMSG_LEN(2 * sizeof(int)));
    int received[2];
    memcpy(received, CMSG_DATA(header), sizeof(received));
    close(source);
    for (int fd : received) {
        assert(fd >= 0 && (fcntl(fd, F_GETFD) & FD_CLOEXEC));
        close(fd);
    }
    assert(lmkd_unregister_service_instance(sockets[0], value.pid, value.boot, value.instance) ==
           0);
    assert(recv(sockets[1], packet, sizeof(packet), 0) == 6 * static_cast<ssize_t>(sizeof(int)));
    assert(lmkd_pack_get_cmd(packet) == LMK_SERVICE_REMOVE &&
           lmkd_unpack_u64(packet, 4) == value.instance);
    assert(lmkd_test_kill_service_instance(sockets[0], value.pid, value.boot, value.instance) == 0);
    assert(recv(sockets[1], packet, sizeof(packet), 0) == 6 * static_cast<ssize_t>(sizeof(int)) &&
           lmkd_pack_get_cmd(packet) == LMK_SERVICE_TEST_KILL);
    assert(lmkd_register_service_instance(sockets[0], &value, -1, -1) == -1 && errno == EINVAL);
    assert(lmkd_unregister_service_instance(sockets[0], value.pid, 0, value.instance) == -1 &&
           errno == EINVAL);
    assert(recv(sockets[1], packet, sizeof(packet), MSG_DONTWAIT) == -1 && errno == EAGAIN);
    close(sockets[0]);
    close(sockets[1]);
}
