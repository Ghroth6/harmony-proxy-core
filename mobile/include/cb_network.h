#ifndef CB_NETWORK_H
#define CB_NETWORK_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Network contract 1; strict non-VPN complete snapshot <=65536 bytes,
 * operation <=128 safeId bytes, output <=8192. The actual core owner submits
 * a true platform snapshot before starting. Busy includes pending transfers
 * and incomplete cleanup. Cancellation/join precedes whole atomic publication.
 * A published receipt confirms submitted observations, not their platform truth.
 * Status/output ownership and cb_free_v1 follow cb_content.h. */
int32_t cb_network_contract_version_v1(void);
int32_t cb_network_submit_v1(const uint8_t *snapshot, uint32_t snapshot_size,
    const uint8_t *operation, uint32_t operation_size,
    uint8_t **output, uint32_t *output_size);
#ifdef __cplusplus
}
#endif
#endif
