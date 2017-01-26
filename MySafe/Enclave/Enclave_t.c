#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_create_valut_file(void* pms)
{
	ms_create_valut_file_t* ms = SGX_CAST(ms_create_valut_file_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_path = ms->ms_path;
	size_t _len_path = 251;
	char* _in_path = NULL;
	char* _tmp_password = ms->ms_password;
	size_t _tmp_len = ms->ms_len;
	size_t _len_password = _tmp_len;
	char* _in_password = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_create_valut_file_t));
	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);

	if (_tmp_path != NULL) {
		_in_path = (char*)malloc(_len_path);
		if (_in_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_path, _tmp_path, _len_path);
	}
	if (_tmp_password != NULL) {
		_in_password = (char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_password, _tmp_password, _len_password);
	}
	ms->ms_retval = create_valut_file(_in_path, _in_password, _tmp_len);
err:
	if (_in_path) free(_in_path);
	if (_in_password) free(_in_password);

	return status;
}

static sgx_status_t SGX_CDECL sgx_load_valut_from_file(void* pms)
{
	ms_load_valut_from_file_t* ms = SGX_CAST(ms_load_valut_from_file_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_path = ms->ms_path;
	size_t _len_path = 251;
	char* _in_path = NULL;
	char* _tmp_password = ms->ms_password;
	size_t _tmp_len = ms->ms_len;
	size_t _len_password = _tmp_len;
	char* _in_password = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_load_valut_from_file_t));
	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);

	if (_tmp_path != NULL) {
		_in_path = (char*)malloc(_len_path);
		if (_in_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_path, _tmp_path, _len_path);
	}
	if (_tmp_password != NULL) {
		_in_password = (char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_password, _tmp_password, _len_password);
	}
	ms->ms_retval = load_valut_from_file(_in_path, _in_password, _tmp_len);
err:
	if (_in_path) free(_in_path);
	if (_in_password) free(_in_password);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_encrypt_file(void* pms)
{
	ms_enclave_encrypt_file_t* ms = SGX_CAST(ms_enclave_encrypt_file_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_path = ms->ms_path;
	size_t _len_path = 251;
	char* _in_path = NULL;
	char* _tmp_new_path = ms->ms_new_path;
	size_t _len_new_path = 251;
	char* _in_new_path = NULL;
	char* _tmp_file_password = ms->ms_file_password;
	size_t _tmp_len = ms->ms_len;
	size_t _len_file_password = _tmp_len;
	char* _in_file_password = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_enclave_encrypt_file_t));
	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);
	CHECK_UNIQUE_POINTER(_tmp_new_path, _len_new_path);
	CHECK_UNIQUE_POINTER(_tmp_file_password, _len_file_password);

	if (_tmp_path != NULL) {
		_in_path = (char*)malloc(_len_path);
		if (_in_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_path, _tmp_path, _len_path);
	}
	if (_tmp_new_path != NULL) {
		_in_new_path = (char*)malloc(_len_new_path);
		if (_in_new_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_new_path, _tmp_new_path, _len_new_path);
	}
	if (_tmp_file_password != NULL) {
		_in_file_password = (char*)malloc(_len_file_password);
		if (_in_file_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_file_password, _tmp_file_password, _len_file_password);
	}
	ms->ms_retval = enclave_encrypt_file(_in_path, _in_new_path, _in_file_password, _tmp_len);
err:
	if (_in_path) free(_in_path);
	if (_in_new_path) free(_in_new_path);
	if (_in_file_password) free(_in_file_password);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_decrypt_file(void* pms)
{
	ms_enclave_decrypt_file_t* ms = SGX_CAST(ms_enclave_decrypt_file_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_path = ms->ms_path;
	size_t _len_path = 251;
	char* _in_path = NULL;
	char* _tmp_new_path = ms->ms_new_path;
	size_t _len_new_path = 251;
	char* _in_new_path = NULL;
	char* _tmp_file_password = ms->ms_file_password;
	size_t _tmp_len = ms->ms_len;
	size_t _len_file_password = _tmp_len;
	char* _in_file_password = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_enclave_decrypt_file_t));
	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);
	CHECK_UNIQUE_POINTER(_tmp_new_path, _len_new_path);
	CHECK_UNIQUE_POINTER(_tmp_file_password, _len_file_password);

	if (_tmp_path != NULL) {
		_in_path = (char*)malloc(_len_path);
		if (_in_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_path, _tmp_path, _len_path);
	}
	if (_tmp_new_path != NULL) {
		_in_new_path = (char*)malloc(_len_new_path);
		if (_in_new_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_new_path, _tmp_new_path, _len_new_path);
	}
	if (_tmp_file_password != NULL) {
		_in_file_password = (char*)malloc(_len_file_password);
		if (_in_file_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_file_password, _tmp_file_password, _len_file_password);
	}
	ms->ms_retval = enclave_decrypt_file(_in_path, _in_new_path, _in_file_password, _tmp_len);
err:
	if (_in_path) free(_in_path);
	if (_in_new_path) free(_in_new_path);
	if (_in_file_password) free(_in_file_password);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_close_valut(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	enclave_close_valut();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_create_valut_file, 0},
		{(void*)(uintptr_t)sgx_load_valut_from_file, 0},
		{(void*)(uintptr_t)sgx_enclave_encrypt_file, 0},
		{(void*)(uintptr_t)sgx_enclave_decrypt_file, 0},
		{(void*)(uintptr_t)sgx_enclave_close_valut, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[12][5];
} g_dyn_entry_table = {
	12,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL encalve_write_file(uint8_t* retval, char* path, char* buffer, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = 100;
	size_t _len_buffer = len;

	ms_encalve_write_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_encalve_write_file_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;
	ocalloc_size += (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) ? _len_buffer : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_encalve_write_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_encalve_write_file_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy(ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) {
		ms->ms_buffer = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		memcpy(ms->ms_buffer, buffer, _len_buffer);
	} else if (buffer == NULL) {
		ms->ms_buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(0, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL encalve_write_end_of_open_file(uint8_t* retval, char* path, char* buffer, size_t len, int call_type)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = 100;
	size_t _len_buffer = len;

	ms_encalve_write_end_of_open_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_encalve_write_end_of_open_file_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;
	ocalloc_size += (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) ? _len_buffer : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_encalve_write_end_of_open_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_encalve_write_end_of_open_file_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy(ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) {
		ms->ms_buffer = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		memcpy(ms->ms_buffer, buffer, _len_buffer);
	} else if (buffer == NULL) {
		ms->ms_buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	ms->ms_call_type = call_type;
	status = sgx_ocall(1, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL encalve_read_file(uint8_t* retval, char* path, char* buffer, size_t len, size_t* actual_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = 100;
	size_t _len_buffer = len;
	size_t _len_actual_len = sizeof(*actual_len);

	ms_encalve_read_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_encalve_read_file_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;
	ocalloc_size += (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) ? _len_buffer : 0;
	ocalloc_size += (actual_len != NULL && sgx_is_within_enclave(actual_len, _len_actual_len)) ? _len_actual_len : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_encalve_read_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_encalve_read_file_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy(ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) {
		ms->ms_buffer = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		memset(ms->ms_buffer, 0, _len_buffer);
	} else if (buffer == NULL) {
		ms->ms_buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	if (actual_len != NULL && sgx_is_within_enclave(actual_len, _len_actual_len)) {
		ms->ms_actual_len = (size_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_actual_len);
		memset(ms->ms_actual_len, 0, _len_actual_len);
	} else if (actual_len == NULL) {
		ms->ms_actual_len = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;
	if (buffer) memcpy((void*)buffer, ms->ms_buffer, _len_buffer);
	if (actual_len) memcpy((void*)actual_len, ms->ms_actual_len, _len_actual_len);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL encalve_read_part_open_file(uint8_t* retval, char* path, char* buffer, size_t len, size_t* actual_len, int call_type)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = 100;
	size_t _len_buffer = len;
	size_t _len_actual_len = sizeof(*actual_len);

	ms_encalve_read_part_open_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_encalve_read_part_open_file_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;
	ocalloc_size += (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) ? _len_buffer : 0;
	ocalloc_size += (actual_len != NULL && sgx_is_within_enclave(actual_len, _len_actual_len)) ? _len_actual_len : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_encalve_read_part_open_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_encalve_read_part_open_file_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy(ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (buffer != NULL && sgx_is_within_enclave(buffer, _len_buffer)) {
		ms->ms_buffer = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_buffer);
		memset(ms->ms_buffer, 0, _len_buffer);
	} else if (buffer == NULL) {
		ms->ms_buffer = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	if (actual_len != NULL && sgx_is_within_enclave(actual_len, _len_actual_len)) {
		ms->ms_actual_len = (size_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_actual_len);
		memset(ms->ms_actual_len, 0, _len_actual_len);
	} else if (actual_len == NULL) {
		ms->ms_actual_len = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_call_type = call_type;
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;
	if (buffer) memcpy((void*)buffer, ms->ms_buffer, _len_buffer);
	if (actual_len) memcpy((void*)actual_len, ms->ms_actual_len, _len_actual_len);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL encalve_file_size(char* path, size_t* file_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = 100;
	size_t _len_file_size = sizeof(*file_size);

	ms_encalve_file_size_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_encalve_file_size_t);
	void *__tmp = NULL;

	ocalloc_size += (path != NULL && sgx_is_within_enclave(path, _len_path)) ? _len_path : 0;
	ocalloc_size += (file_size != NULL && sgx_is_within_enclave(file_size, _len_file_size)) ? _len_file_size : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_encalve_file_size_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_encalve_file_size_t));

	if (path != NULL && sgx_is_within_enclave(path, _len_path)) {
		ms->ms_path = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_path);
		memcpy(ms->ms_path, path, _len_path);
	} else if (path == NULL) {
		ms->ms_path = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (file_size != NULL && sgx_is_within_enclave(file_size, _len_file_size)) {
		ms->ms_file_size = (size_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_file_size);
		memset(ms->ms_file_size, 0, _len_file_size);
	} else if (file_size == NULL) {
		ms->ms_file_size = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(4, ms);

	if (file_size) memcpy((void*)file_size, ms->ms_file_size, _len_file_size);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL my_print(char* str, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = len;

	ms_my_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_my_print_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_my_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_my_print_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy(ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(5, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL my_print2(int num)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_my_print2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_my_print2_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_my_print2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_my_print2_t));

	ms->ms_num = num;
	status = sgx_ocall(6, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(7, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(8, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(10, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(11, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
