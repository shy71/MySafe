#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_create_valut_file_t {
	sgx_status_t ms_retval;
	char* ms_path;
	char* ms_password;
	size_t ms_len;
} ms_create_valut_file_t;

typedef struct ms_load_valut_from_file_t {
	sgx_status_t ms_retval;
	char* ms_path;
	char* ms_password;
	size_t ms_len;
} ms_load_valut_from_file_t;

typedef struct ms_enclave_encrypt_file_t {
	sgx_status_t ms_retval;
	char* ms_path;
	char* ms_new_path;
	char* ms_file_password;
	size_t ms_len;
} ms_enclave_encrypt_file_t;

typedef struct ms_enclave_decrypt_file_t {
	sgx_status_t ms_retval;
	char* ms_path;
	char* ms_new_path;
	char* ms_file_password;
	size_t ms_len;
} ms_enclave_decrypt_file_t;


typedef struct ms_encalve_write_file_t {
	uint8_t ms_retval;
	char* ms_path;
	char* ms_buffer;
	size_t ms_len;
} ms_encalve_write_file_t;

typedef struct ms_encalve_write_end_of_open_file_t {
	uint8_t ms_retval;
	char* ms_path;
	char* ms_buffer;
	size_t ms_len;
	int ms_call_type;
} ms_encalve_write_end_of_open_file_t;

typedef struct ms_encalve_read_file_t {
	uint8_t ms_retval;
	char* ms_path;
	char* ms_buffer;
	size_t ms_len;
	size_t* ms_actual_len;
} ms_encalve_read_file_t;

typedef struct ms_encalve_read_part_open_file_t {
	uint8_t ms_retval;
	char* ms_path;
	char* ms_buffer;
	size_t ms_len;
	size_t* ms_actual_len;
	int ms_call_type;
} ms_encalve_read_part_open_file_t;

typedef struct ms_encalve_file_size_t {
	char* ms_path;
	size_t* ms_file_size;
} ms_encalve_file_size_t;

typedef struct ms_my_print_t {
	char* ms_str;
	size_t ms_len;
} ms_my_print_t;

typedef struct ms_my_print2_t {
	int ms_num;
} ms_my_print2_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_encalve_write_file(void* pms)
{
	ms_encalve_write_file_t* ms = SGX_CAST(ms_encalve_write_file_t*, pms);
	ms->ms_retval = encalve_write_file(ms->ms_path, ms->ms_buffer, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_encalve_write_end_of_open_file(void* pms)
{
	ms_encalve_write_end_of_open_file_t* ms = SGX_CAST(ms_encalve_write_end_of_open_file_t*, pms);
	ms->ms_retval = encalve_write_end_of_open_file(ms->ms_path, ms->ms_buffer, ms->ms_len, ms->ms_call_type);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_encalve_read_file(void* pms)
{
	ms_encalve_read_file_t* ms = SGX_CAST(ms_encalve_read_file_t*, pms);
	ms->ms_retval = encalve_read_file(ms->ms_path, ms->ms_buffer, ms->ms_len, ms->ms_actual_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_encalve_read_part_open_file(void* pms)
{
	ms_encalve_read_part_open_file_t* ms = SGX_CAST(ms_encalve_read_part_open_file_t*, pms);
	ms->ms_retval = encalve_read_part_open_file(ms->ms_path, ms->ms_buffer, ms->ms_len, ms->ms_actual_len, ms->ms_call_type);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_encalve_file_size(void* pms)
{
	ms_encalve_file_size_t* ms = SGX_CAST(ms_encalve_file_size_t*, pms);
	encalve_file_size(ms->ms_path, ms->ms_file_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_my_print(void* pms)
{
	ms_my_print_t* ms = SGX_CAST(ms_my_print_t*, pms);
	my_print(ms->ms_str, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_my_print2(void* pms)
{
	ms_my_print2_t* ms = SGX_CAST(ms_my_print2_t*, pms);
	my_print2(ms->ms_num);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[12];
} ocall_table_Enclave = {
	12,
	{
		(void*)(uintptr_t)Enclave_encalve_write_file,
		(void*)(uintptr_t)Enclave_encalve_write_end_of_open_file,
		(void*)(uintptr_t)Enclave_encalve_read_file,
		(void*)(uintptr_t)Enclave_encalve_read_part_open_file,
		(void*)(uintptr_t)Enclave_encalve_file_size,
		(void*)(uintptr_t)Enclave_my_print,
		(void*)(uintptr_t)Enclave_my_print2,
		(void*)(uintptr_t)Enclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t create_valut_file(sgx_enclave_id_t eid, sgx_status_t* retval, char* path, char* password, size_t len)
{
	sgx_status_t status;
	ms_create_valut_file_t ms;
	ms.ms_path = path;
	ms.ms_password = password;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t load_valut_from_file(sgx_enclave_id_t eid, sgx_status_t* retval, char* path, char* password, size_t len)
{
	sgx_status_t status;
	ms_load_valut_from_file_t ms;
	ms.ms_path = path;
	ms.ms_password = password;
	ms.ms_len = len;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_encrypt_file(sgx_enclave_id_t eid, sgx_status_t* retval, char* path, char* new_path, char* file_password, size_t len)
{
	sgx_status_t status;
	ms_enclave_encrypt_file_t ms;
	ms.ms_path = path;
	ms.ms_new_path = new_path;
	ms.ms_file_password = file_password;
	ms.ms_len = len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_decrypt_file(sgx_enclave_id_t eid, sgx_status_t* retval, char* path, char* new_path, char* file_password, size_t len)
{
	sgx_status_t status;
	ms_enclave_decrypt_file_t ms;
	ms.ms_path = path;
	ms.ms_new_path = new_path;
	ms.ms_file_password = file_password;
	ms.ms_len = len;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_close_valut(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, NULL);
	return status;
}

