#ifndef CB_LOG_H
#define CB_LOG_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// The callback and context must remain valid for the lifetime of this process.
// message is borrowed only for the synchronous callback; copy it before return
// if retaining it. Callbacks may be concurrent; never log back into the core.
// Levels: 0 debug, 1 info, 2 warning, 3 error, 4 fatal, 5 panic.
typedef void (*cb_log_fn_v1)(void *context, int32_t level, const uint8_t *message, uint64_t length);
// 0 installed; -1 invalid callback or an output is already installed.
int32_t cb_log_install_v1(cb_log_fn_v1 callback, void *context);
#ifdef __cplusplus
}
#endif
#endif
