#include "Enclave_t.h"
// sample_enclave.cpp
#include <string.h>
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

#include "sgx_tseal.h"
#define TEXT_LENGTH 20
static uint8_t main_key[16];
void seal(uint8_t *data_buffer, size_t data_size, uint8_t *sealed_data, size_t buffer_size, size_t* actual_size)
{
	uint32_t sealed_size = sgx_calc_sealed_data_size(0, data_size);
	if (sealed_size == UINT32_MAX)
	{
		*actual_size = -1;
		return;//Error
	}
	else if (sealed_size > buffer_size)
	{
		*actual_size = sealed_size;
		return;//Error
	}
	uint8_t* sealed_data_space = new uint8_t[sealed_size];
	sgx_status_t res = sgx_seal_data(0, NULL, data_size, data_buffer, sealed_size, (sgx_sealed_data_t *)sealed_data_space);
	if (res)
	{
		*actual_size = -res;
		return;
	}
	*actual_size = sealed_size;
	memcpy(sealed_data, sealed_data_space, sealed_size);
}
int seal_ex(uint8_t *data_buffer, size_t data_size, uint8_t *sealed_data, size_t buffer_size, size_t* actual_size)
{
	uint32_t sealed_size = sgx_calc_sealed_data_size(0, data_size);
	if (sealed_size == UINT32_MAX)
		return -1;//error
	else if (sealed_size > buffer_size)
	{
		*actual_size = sealed_size;
		return -2;//error
	}
	uint8_t* sealed_data_space = new uint8_t[sealed_size];
	sgx_attributes_t attr;
	attr.flags = SGX_FLAGS_PROVISION_KEY | SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
	attr.xfrm = 0;
	sgx_status_t res = sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, attr, NULL, NULL, NULL, data_size, data_buffer, sealed_size, (sgx_sealed_data_t *)sealed_data_space);
	if (res)
		return res;
	*actual_size = sealed_size;
	memcpy(sealed_data, sealed_data_space, sealed_size);
	return SGX_SUCCESS;
}
int unseal(uint8_t *sealed_data, size_t sealed_size, uint8_t *plain_data, size_t buffer_size, size_t* actual_size)
{
	uint8_t* sealed_space = new uint8_t[sealed_size];
	memcpy(sealed_space, sealed_data, sealed_size);
	uint32_t plain_data_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)sealed_space);
	if (plain_data_size == UINT32_MAX)
		return -1;//error
	else if (plain_data_size > buffer_size)
	{
		return -2;
		*actual_size = plain_data_size;
	}
	uint8_t* plain_data_space = new uint8_t[plain_data_size];
	sgx_status_t res = sgx_unseal_data((sgx_sealed_data_t *)sealed_space, NULL, NULL, plain_data_space, &plain_data_size);
	if (res)
		return res;
	*actual_size = plain_data_size;
	memcpy(plain_data, plain_data_space, plain_data_size);
	return 0;
}
void get_sha256_hash(char * password, size_t len, uint8_t* result)
{
	sgx_sha_state_handle_t handle;
	sgx_sha256_init(&handle);
	sgx_sha256_update((uint8_t*)password, len, handle);
	sgx_sha256_get_hash(handle, (sgx_sha256_hash_t*)result);
}
sgx_status_t create_valut_file(char* password, size_t len, uint8_t *sealed_data, size_t buffer_size, size_t *actual_size)
{
	uint8_t* hash = new uint8_t[32];
	get_sha256_hash(password, len, hash);
	uint8_t* master_key = new uint8_t[16], *iv = new uint8_t[12];
	uint8_t* encrypted = new uint8_t[44];
	sgx_aes_gcm_128bit_tag_t* out_mac = (sgx_aes_gcm_128bit_tag_t*) new uint8_t[SGX_AESGCM_MAC_SIZE];
	sgx_read_rand(master_key, 16);
	sgx_read_rand(iv, 12);
	sgx_status_t res = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*)hash, master_key, 16, encrypted, iv, 12, NULL, 0, out_mac);
	if (res)
		return res;//Error
	memcpy(encrypted + 16, iv, 12);
	memcpy(encrypted + 28, out_mac, 16);
	memcpy(main_key, master_key, 16);
	int result = seal_ex(encrypted, 44, sealed_data, buffer_size, actual_size);
	if (result == -1)
		return SGX_ERROR_UNEXPECTED;
	else if (result == -2)
		return SGX_ERROR_OUT_OF_MEMORY;
	else if (result > 0)
		return (sgx_status_t)result;
	return SGX_SUCCESS;
}
sgx_status_t load_valut_from_file(char* password, size_t len, uint8_t *sealed_data, size_t sealed_size)
{
	uint8_t* hash = new uint8_t[32];
	get_sha256_hash(password, len, hash);
	size_t decrypted_size = 44;
	uint8_t* decrypted = new uint8_t[decrypted_size];
	uint8_t* master_key = new uint8_t[16], *iv = new uint8_t[12];
	sgx_aes_gcm_128bit_tag_t* out_mac = (sgx_aes_gcm_128bit_tag_t*) new uint8_t[SGX_AESGCM_MAC_SIZE], *old_mac = (sgx_aes_gcm_128bit_tag_t*) new uint8_t[SGX_AESGCM_MAC_SIZE];
	int result = unseal(sealed_data, sealed_size, decrypted, decrypted_size, &decrypted_size);
	if (result == -1)
		return SGX_ERROR_MAC_MISMATCH;
	else if (result == -2)
		return SGX_ERROR_OUT_OF_MEMORY;
	else if (result > 0)
		return (sgx_status_t)result;
	memcpy(iv, decrypted + 16, 12);
	memcpy(old_mac, decrypted + 28, 16);
	sgx_status_t res = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t*)hash, decrypted, 16, master_key, iv, 12, NULL, 0, old_mac);
	if (res)
		return res;
	memcpy(main_key, master_key, 16);
	return SGX_SUCCESS;
}