#include "Enclave_t.h"
// sample_enclave.cpp
#include<istream>
#include <string.h>
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

#include "sgx_tseal.h"
#define DEFAULT_SEALED_SIZE 3000
#define DEFAULT_DECRYPTED_KEY_SIZE 44
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
	attr.flags = SGX_FLAGS_PROVISION_KEY | SGX_FLAGS_LICENSE_KEY | SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
	attr.xfrm = 0;
	sgx_status_t res = sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, attr, NULL, NULL, NULL, data_size, data_buffer, sealed_size, (sgx_sealed_data_t *)sealed_data_space);
	if (res)
		return res;
	*actual_size = sealed_size;
	memcpy(sealed_data, sealed_data_space, sealed_size);
	delete[] sealed_data_space;
	return SGX_SUCCESS;
}
int unseal(uint8_t *sealed_data, size_t sealed_size, uint8_t *plain_data, size_t buffer_size)
{
	uint8_t* sealed_space = new uint8_t[sealed_size];
	memcpy(sealed_space, sealed_data, sealed_size);
	uint32_t plain_data_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)sealed_space);
	if (plain_data_size == UINT32_MAX)
		return -1;//error
	else if (plain_data_size > buffer_size)
	{
		return -plain_data_size;
	}
	uint8_t* plain_data_space = new uint8_t[plain_data_size];
	sgx_status_t res = sgx_unseal_data((sgx_sealed_data_t *)sealed_space, NULL, NULL, plain_data_space, &plain_data_size);
	if (res)
		return res;
	memcpy(plain_data, plain_data_space, plain_data_size);
	delete[] sealed_space, plain_data_space;
	return SGX_SUCCESS;
}
void get_sha256_hash(char * password, size_t len, sgx_sha256_hash_t* result)
{
	sgx_sha_state_handle_t handle;
	sgx_sha256_init(&handle);
	sgx_sha256_update((uint8_t*)password, len, handle);
	sgx_sha256_get_hash(handle, result);
}
sgx_status_t create_valut_file(char * path,char* password, size_t len)
{
	size_t sealed_size= DEFAULT_SEALED_SIZE;
	uint8_t sealed_data[DEFAULT_SEALED_SIZE];
	sgx_sha256_hash_t hash;
	get_sha256_hash(password, len,&hash);
	uint8_t master_key[16], iv[12];
	uint8_t encrypted[44];
	sgx_aes_gcm_128bit_tag_t out_mac;
	sgx_read_rand(master_key, 16);
	sgx_read_rand(iv, 12);
	sgx_status_t res = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*)hash, master_key, 16, encrypted, iv, 12, NULL, 0, &out_mac);
	if (res)
		return res;//Error
	memcpy(encrypted + 16, iv, 12);
	memcpy(encrypted + 28, out_mac, 16);
	memcpy(main_key, master_key, 16);
	uint8_t result = seal_ex(encrypted, 44, sealed_data, sealed_size, &sealed_size);
	if (result == -1)
		return SGX_ERROR_UNEXPECTED;
	else if (result == -2)
		return SGX_ERROR_OUT_OF_MEMORY;
	else if (result > 0)
		return (sgx_status_t)result;
	encalve_write_file(&result, path, (char *)sealed_data, sealed_size);
	if(result)
	{
		return SGX_ERROR_FILE_BAD_STATUS;
	}
	return SGX_SUCCESS;
}
sgx_status_t load_valut_from_file(char * path, char* password, size_t len)
{
	uint8_t sealed_data[DEFAULT_SEALED_SIZE];
	uint8_t result;
	encalve_read_file(&result, path, (char *)sealed_data, DEFAULT_SEALED_SIZE,NULL);
	if (result)
	{
		return SGX_ERROR_FILE_BAD_STATUS;
	}
	sgx_sha256_hash_t hash;
	get_sha256_hash(password, len, &hash);
	uint8_t decrypted [DEFAULT_DECRYPTED_KEY_SIZE];
	uint8_t master_key[16], iv[12];
	sgx_aes_gcm_128bit_tag_t old_mac;
	result = unseal(sealed_data, DEFAULT_SEALED_SIZE, decrypted, DEFAULT_DECRYPTED_KEY_SIZE);
	if (result == -1)
		return SGX_ERROR_MAC_MISMATCH;
	else if (result >0)
		return SGX_ERROR_OUT_OF_MEMORY;
	else if (result > 0)
		return (sgx_status_t)result;
	memcpy(iv, decrypted + 16, 12);
	memcpy(old_mac, decrypted + 28, 16);
	sgx_status_t res = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t*)hash, decrypted, 16, master_key, iv, 12, NULL, 0, &old_mac);
	if (res)
		return res;
	memcpy(main_key, master_key, 16);
	return SGX_SUCCESS;
}
sgx_status_t enclave_encrypt_file(char * path,  char * file_password, size_t len)
{
	sgx_sha256_hash_t hash;
	get_sha256_hash(file_password, len, &hash);
	uint8_t iv[12],iv2[12];
	uint8_t file_key[16];
	sgx_aes_gcm_128bit_tag_t out_mac, out_mac2;
	sgx_read_rand(iv, 12);
	sgx_read_rand(iv2, 12);
	uint8_t result;
	sgx_status_t res = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*)hash, main_key, 16, file_key, iv, 12, NULL, 0, &out_mac);
	my_print((char *)file_key,16);
	if (res)
		return res;//Error
	size_t size_input;
	 encalve_file_size(path,&size_input);
	 my_print2(size_input);

	uint8_t *input = new uint8_t[size_input];
	encalve_read_file(&result, path, (char *)input, size_input, &size_input);
	my_print((char *)input, 100);
	my_print((char *)input + 56, 100);

	//uint8_t *pointer = new uint8_t;
	//get_file_istream(path, pointer, size,0);
	memcpy(path + strlen(path), ".ens", 5);
	uint8_t *cipher_text = new uint8_t[size_input + 56];

	sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*)file_key, input, size_input, cipher_text+56, iv2, 12, NULL, 0, &out_mac2);
	memcpy(cipher_text, iv, 12);
	memcpy(cipher_text +12, out_mac, 16);
	memcpy(cipher_text+28 , iv2, 12);
	memcpy(cipher_text +28+ 12, out_mac2, 16);
	my_print((char *)cipher_text + 28 , 12);
	my_print((char *)cipher_text + 28 + 12, 16);
	my_print((char *)cipher_text + 56, 20);
	encalve_write_file(&result, path, (char * )cipher_text, size_input +56);
	if (result)
	{
		return SGX_ERROR_FILE_BAD_STATUS;
	}
	delete[] cipher_text, input;
	return SGX_SUCCESS;
}
sgx_status_t enclave_decrypt_file(char * path,char *newpath, char * file_password, size_t len)
{
	uint8_t result;
	uint8_t data[56];
	encalve_read_file(&result,path,(char*) data, 56, NULL);
	if (result)
	{
		return SGX_ERROR_FILE_BAD_STATUS;
	}
	sgx_sha256_hash_t hash;
	get_sha256_hash(file_password, len, &hash);
	uint8_t iv[12], iv2[12];
	uint8_t file_key[16];
	sgx_aes_gcm_128bit_tag_t out_mac, out_mac2;
	memcpy(iv, data, 12);
	memcpy(out_mac,data+12, 16);
	memcpy(iv2, data+28, 12);
	memcpy(out_mac2, data + 28 + 12, 16);
	sgx_status_t res = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*)hash, main_key, 16, file_key, iv, 12, NULL, 0, &out_mac);
	my_print((char *)file_key, 16);
	my_print((char *)iv2, 12);

	my_print((char *)out_mac2, 16);

	if (res)
		return res;//Error	
	size_t size_input;
	encalve_file_size(path, &size_input);
	uint8_t *input = new uint8_t[size_input];
	encalve_read_file(&result, path, (char *)input, size_input, &size_input);
	my_print((char *)input, 100);
	my_print((char *)input +56, 100);




	uint8_t *plain_text = new uint8_t[size_input - 56];
	res = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t*)file_key, input +56, size_input -56, plain_text, iv2, 12, NULL, 0, &out_mac2);
	if (res)
		return res;//Error
	my_print((char *)plain_text, size_input + 56);
	encalve_write_file(&result, newpath,(char *) plain_text, size_input - 56);
	if (result)
	{
		return SGX_ERROR_FILE_BAD_STATUS;
	}
	delete[] plain_text, input;
	return SGX_SUCCESS;
}
void enclave_close_valut()
{
	for (int i = 0; i < 16; i++)
		main_key[i] = NULL;
}