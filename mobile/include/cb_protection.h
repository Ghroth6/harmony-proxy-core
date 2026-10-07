#ifndef CB_PROTECTION_V1_H
#define CB_PROTECTION_V1_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

// Socket protection ABI 1 is independent of the unchanged validation ABI.
// The callback is synchronous in RawConn.Control. borrowed_fd belongs to the
// core and is valid only until callback return. Duplicate it before queuing.
// Keep callback/context alive until unregister returns 0. A busy unregister
// has already closed admission; retry after the in-flight callback returns.
typedef int32_t (*cb_protect_socket_fn_v1)(void *context, uint64_t generation,
    uint64_t request_id, int32_t borrowed_fd);

// generation: 1..INT32_MAX, strictly increasing for this process.
// Status: 0 success, 1 invalid, 2 inactive, 3 busy, 4 protection failed,
// 5 queue full, 6 cancelled, 7 timeout, 8 environment invalid,
// 9 platform failure, 10 cleanup unknown. Nonzero never permits connection.
int32_t cb_protection_register_v1(uint64_t generation,
    cb_protect_socket_fn_v1 callback, void *context);
int32_t cb_protection_unregister_v1(uint64_t generation);

// Diagnostic orchestration only: one unconnected IPv4 TCP socket; no bind,
// connect or send. request_id: 1..INT64_MAX; production uses the high bit.
int32_t cb_protection_probe_v1(uint64_t generation, uint64_t request_id);

// Reads at most the latest 32 completed probes for the current generation,
// including after unregister. Caller owns all four output scalars. -1 means
// unavailable. POSIX identity is the socket inode; same-object checks use both
// device and inode internally. before/after: 1 observed, 0 absent/different,
// -1 unknown; close: 0 OS close succeeded, 10 close result unknown.
int32_t cb_protection_probe_observation_v1(uint64_t generation,
    uint64_t request_id, int64_t *socket_identity, int32_t *before_socket,
    int32_t *after_same_socket, int32_t *close_result);

#ifdef __cplusplus
}
#endif
#endif
