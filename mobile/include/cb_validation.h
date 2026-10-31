#ifndef CB_VALIDATION_V1_H
#define CB_VALIDATION_V1_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Inputs are borrowed only during the call. The result is allocated by the
// library and MUST be released by cb_free_v1, including invalid/incomplete.
// cb_validate_v1 checks the upstream format only; successful decoding returns
// incomplete with semantic-validation uncovered. Use policy preparation for
// complete configuration semantics. ABI 1 does not authorize runtime start.
int32_t cb_abi_version_v1(void);
int32_t cb_validate_v1(const uint8_t *input, uint32_t input_size,
                       const uint8_t *operation, uint32_t operation_size,
                       uint8_t **output, uint32_t *output_size);
void cb_free_v1(void *output);
#ifdef __cplusplus
}
#endif
#endif
