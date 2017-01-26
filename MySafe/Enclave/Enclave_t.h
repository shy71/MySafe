#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t create_valut_file(char* path, char* password, size_t len);
sgx_status_t load_valut_from_file(char* path, char* password, size_t len);
sgx_status_t enclave_encrypt_file(char* path, char* new_path, char* file_password, size_t len);
sgx_status_t enclave_decrypt_file(char* path, char* new_path, char* file_password, size_t len);
void enclave_close_valut();

sgx_status_t SGX_CDECL encalve_write_file(uint8_t* retval, char* path, char* buffer, size_t len);
sgx_status_t SGX_CDECL encalve_write_end_of_open_file(uint8_t* retval, char* path, char* buffer, size_t len, int call_type);
sgx_status_t SGX_CDECL encalve_read_file(uint8_t* retval, char* path, char* buffer, size_t len, size_t* actual_len);
sgx_status_t SGX_CDECL encalve_read_part_open_file(uint8_t* retval, char* path, char* buffer, size_t len, size_t* actual_len, int call_type);
sgx_status_t SGX_CDECL encalve_file_size(char* path, size_t* file_size);
sgx_status_t SGX_CDECL my_print(char* str, size_t len);
sgx_status_t SGX_CDECL my_print2(int num);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
