#ifndef CB_RUNTIME_H
#define CB_RUNTIME_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Independent from cb_abi_version_v1. Resolve this and all three operations
 * before duplicating a TUN descriptor. The retained v1 symbols return contract
 * version 5 and reject version-1/2/3/4 request shapes. Version 5 has the schema in
 * mobile/runtime/contract.go and mobile/README.md. */
int32_t cb_runtime_contract_version_v1(void);

/* Every actually valid owned_tun_fd is CONSUMED immediately on entry, before
 * checking any other argument (including output pointers). Do not close it
 * again after entering, even if status is nonzero or output is corrupt.
 * generation is 1..INT32_MAX; transfer_id is independently allocated, nonzero,
 * strictly increasing. request JSON mirrors both scalars (generation:number,
 * transferId:canonical decimal string). Borrowed byte buffers are copied.
 * request.networkGeneration is mandatory and positive for every input, and
 * must identify the actual matching online path accepted by the core.
 * Receipt.networkGeneration is zero until accepted against real core state.
 * Every request carries the strict preparedPolicy value with
 * four independently verified identities. Its immutable manifest remains
 * separate from later actual resource acquisition/adoption observations.
 * Input/request byte lengths must fit signed C.int (INT32_MAX).
 * Observation output uses the embedding application's configured byte budget
 * (1048576 bytes in clashoh), independently of input and forwarding capacity.
 * No fd is acquired by query/stop. transfer_id=0 queries the run; positive IDs
 * query that EXACT entered handoff. Missing handoffs return unknown, never an
 * older clean run. Duplicate/non-monotonic IDs remain ownership faults.
 * Start observes <=5000 ms and stop <=10000 ms; cleanup continues independently.
 * ABI status: 0=bounded receipt returned, 1=invalid output/buffer ABI arguments,
 * 2=internal/output failure. Runtime success is only in the typed receipt.
 * All nonnull output buffers are owned by the caller and freed with cb_free_v1.
 * Valid output pointers are initialized to NULL/0 before work/allocation. */
int32_t cb_runtime_start_v1(uint64_t generation, uint64_t transfer_id,
    int32_t owned_tun_fd, uint8_t *input, uint32_t input_size,
    uint8_t *request, uint32_t request_size, uint8_t **output,
    uint32_t *output_size);
int32_t cb_runtime_stop_v1(uint64_t generation, uint8_t **output,
    uint32_t *output_size);
int32_t cb_runtime_query_v1(uint64_t generation, uint64_t transfer_id,
    uint8_t **output, uint32_t *output_size);

#ifdef __cplusplus
}
#endif
#endif
