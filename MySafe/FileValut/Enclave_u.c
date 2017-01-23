#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_create_valut_file_t {
	sgx_status_t ms_retval;
	char* ms_password;
	size_t ms_len;
	uint8_t* ms_sealed_data;
	size_t ms_buffer_size;
	size_t* ms_actual_size;
} ms_create_valut_file_t;

typedef struct ms_load_valut_from_file_t {
	sgx_status_t ms_retval;
	char* ms_password;
	size_t ms_len;
	uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_load_valut_from_file_t;

typedef struct ms_write_file_t {
	char* ms_path;
	char* ms_buffer;
	size_t ms_len;
} ms_write_file_t;

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

static sgx_status_t SGX_CDECL Enclave_write_file(void* pms)
{
	ms_write_file_t* ms = SGX_CAST(ms_write_file_t*, pms);
	write_file(ms->ms_path, ms->ms_buffer, ms->ms_len);

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
	void * func_addr[8];
} ocall_table_Enclave = {
	8,
	{
		(void*)(uintptr_t)Enclave_write_file,
		(void*)(uintptr_t)Enclave_my_print,
		(void*)(uintptr_t)Enclave_my_print2,
		(void*)(uintptr_t)Enclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t create_valut_file(sgx_enclave_id_t eid, sgx_status_t* retval, char* password, size_t len, uint8_t* sealed_data, size_t buffer_size, size_t* actual_size)
{
	sgx_status_t status;
	ms_create_valut_file_t ms;
	ms.ms_password = password;
	ms.ms_len = len;
	ms.ms_sealed_data = sealed_data;
	ms.ms_buffer_size = buffer_size;
	ms.ms_actual_size = actual_size;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t load_valut_from_file(sgx_enclave_id_t eid, sgx_status_t* retval, char* password, size_t len, uint8_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status;
	ms_load_valut_from_file_t ms;
	ms.ms_password = password;
	ms.ms_len = len;
	ms.ms_sealed_data = sealed_data;
	ms.ms_sealed_size = sealed_size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

