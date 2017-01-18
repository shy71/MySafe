#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t foo(sgx_enclave_id_t eid, char* buf, size_t len);
sgx_status_t seal(sgx_enclave_id_t eid, uint8_t* data_buffer, size_t data_size, uint8_t* sealed_data, size_t buffer_size, size_t* actual_size);
sgx_status_t unseal(sgx_enclave_id_t eid, uint8_t* sealed_data, size_t sealed_size, uint8_t* plain_data, size_t buffer_size, size_t* actual_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
