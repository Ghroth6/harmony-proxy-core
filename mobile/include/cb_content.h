#ifndef CB_CONTENT_H
#define CB_CONTENT_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Content contract 1. Raw/decoded/node bytes <=1048576, entries <=4096;
 * receipt <=8388608, operation <=128 UTF-8 bytes and safeId characters.
 * Inspection does not download, resolve DNS, apply a candidate or open VPN.
 * Supported nodes have complete deterministic private nodeJson and digest;
 * this is static constructor/cleanup coverage, never remote availability.
 * Inputs are borrowed/copied; output is freed with cb_free_v1. Status 0 means
 * a typed receipt, 1 invalid ABI bounds, 2 internal/output failure. Both valid
 * output pointers are initialized NULL/0 even on errors. */
int32_t cb_content_contract_version_v1(void);
int32_t cb_content_inspect_v1(const uint8_t *input, uint32_t input_size,
    const uint8_t *operation, uint32_t operation_size,
    uint8_t **output, uint32_t *output_size);
#ifdef __cplusplus
}
#endif
#endif
