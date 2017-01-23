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

void SGX_UBRIDGE(SGX_NOCONVENTION, write_file, (char* path, char* buffer, size_t len));
void SGX_UBRIDGE(SGX_NOCONVENTION, my_print, (char* str, size_t len));
void SGX_UBRIDGE(SGX_NOCONVENTION, my_print2, (int num));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t create_valut_file(sgx_enclave_id_t eid, sgx_status_t* retval, char* password, size_t len, uint8_t* sealed_data, size_t buffer_size, size_t* actual_size);
sgx_status_t load_valut_from_file(sgx_enclave_id_t eid, sgx_status_t* retval, char* password, size_t len, uint8_t* sealed_data, size_t sealed_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
