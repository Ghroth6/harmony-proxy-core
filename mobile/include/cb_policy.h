#ifndef CB_POLICY_H
#define CB_POLICY_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Original policy ABI 2, prepared context schema/planner remain 1.
 * Explicit applicationScope all/include; absent means valid legacy include.
 * Raw/control <=1048576, result<=8388608;
 * resources<=128, groups<=512, members<=4096 each/32768 total.
 * storage_root is a trusted native Context path (<=4096 UTF-8), never an RPC
 * root. It binds once and is idempotent only for that same canonical path.
 * Prepare/Plan/Validate open fixed immutable files; they never acquire HTTP.
 * Empty raw is a typed invalid receipt with its actual digest. Other borrowed
 * inputs are copied. Output pointers are initialized NULL/0 on every path.
 * Status0 typed result, 1 bounds/wire/root refusal, 2 internal failure; caller
 * releases successful output with cb_free_v1. */
int32_t cb_policy_contract_version_v1(void);
int32_t cb_policy_storage_root_v1(const uint8_t *root, uint32_t root_size);
int32_t cb_policy_plan_v1(const uint8_t *raw, uint32_t raw_size,
    const uint8_t *available_json, uint32_t available_size,
    const uint8_t *operation, uint32_t operation_size,
    uint8_t **output, uint32_t *output_size);
int32_t cb_policy_validate_v1(const uint8_t *raw, uint32_t raw_size,
    const uint8_t *context_json, uint32_t context_size,
    const uint8_t *operation, uint32_t operation_size,
    uint8_t **output, uint32_t *output_size);
int32_t cb_policy_resources_v1(uint64_t generation,
    const uint8_t *operation, uint32_t operation_size,
    uint8_t **output, uint32_t *output_size);
#ifdef __cplusplus
}
#endif
#endif
