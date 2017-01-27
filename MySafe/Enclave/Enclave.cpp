#include <string.h>

#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

#define DEFAULT_SEALED_SIZE 3000
#define DEFAULT_DECRYPTED_KEY_SIZE 44
#define SIZE_AES_CTR_BLOCK_BYTE 16
#define SIZE_AES_IV 12
#define SHA_256_HASH_SIZE 32
#define CHECK_RESULT(result) if (result) return SGX_ERROR_FILE_BAD_STATUS;

static uint8_t main_key[16];


void get_sha256_hash(char * password, size_t len, sgx_sha256_hash_t* result);

#pragma region 	Sealing Functions
/* seal_ex
* Purpose: This function is used to perform the operation of sealing data
*
* Paramters:
*      data_buffer - [IN] Buffer which contains the data to be sealed
*      data_size - [IN] Length of the data in the data buffer in bytes
*      sealed_data - [OUT] Buffer to hold the sealed data
*      sealed_buffer_size - [IN] Length of the sealed data buffer in bytes
*      actual_size - [OUT] Length of the sealed data that was entered into the buffer
*
* Return Value:
*      sgx_status_t - SGX_SUCESS if the function succeeds
*      If the sealed_data buffer isn't big enough, SGX_ERROR_OUT_OF_MEMORY is returned.
*      If the function fails from any other reason, the matching erroe code is returned.
*/
sgx_status_t seal_ex(uint8_t *data_buffer, size_t data_size, uint8_t *sealed_data, size_t sealed_buffer_size, size_t* actual_size)
{
	uint32_t sealed_size = sgx_calc_sealed_data_size(0, data_size);
	sgx_attributes_t attr;
	if (sealed_size == UINT32_MAX)
		return SGX_ERROR_UNEXPECTED;//error
	else if (sealed_size > sealed_buffer_size)
	{
		*actual_size = sealed_size;
		return SGX_ERROR_OUT_OF_MEMORY;//error
	}
	attr.flags = SGX_FLAGS_PROVISION_KEY | SGX_FLAGS_LICENSE_KEY | SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
	attr.xfrm = 0;
	*actual_size = sealed_size;
	return sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, attr, NULL, NULL, NULL, data_size, data_buffer, sealed_size, (sgx_sealed_data_t *)sealed_data);

}
/* unseal
* Purpose: This function is used to perform the operation of unsealing data
*
* Paramters:
*      data_buffer - [IN] Buffer which contains the sealed data to be unsealed
*      data_size - [IN] Length of the data in the sealed data buffer in bytes
*      unsealed_data - [OUT] Buffer to hold the unsealed data
*      unsealed_data_buffer_size - [IN] Length of the unsealed data buffer in bytes
*
* Return Value:
*      sgx_status_t - SGX_SUCESS if the function succeeds
*      If the unsealed_data buffer isn't big enough, SGX_ERROR_OUT_OF_MEMORY is returned.
*      If the call to the function sgx_get_encrypt_txt_len failed because the sealed data isn't valid, SGX_ERROR_MAC_MISMATCH is returned.
*      If the function fails from any other reason, the matching erroe code is returned.
*/
sgx_status_t unseal(uint8_t *sealed_data, size_t sealed_size, uint8_t *unsealed_data, size_t unsealed_data_buffer_size)
{
	uint32_t plain_data_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)sealed_data);
	if (plain_data_size == UINT32_MAX)
		return SGX_ERROR_MAC_MISMATCH;//error
	else if (plain_data_size > unsealed_data_buffer_size)
		return SGX_ERROR_OUT_OF_MEMORY;
	return sgx_unseal_data((sgx_sealed_data_t *)sealed_data, NULL, NULL, unsealed_data, &plain_data_size);
}
#pragma endregion


#pragma region 	Vault Functions
/* create_vault_file
* Purpose: This function is used to perform the operation of creating a vault file
*
* Paramters:
*      path - [IN] The Path for the vault file
*      password - [IN] The password used to encrypt the vault file
*      len - [IN] Length of the password in bytes

* Return Value:
*      If the function fails from any reason, the matching erroe code is returned.
*/
sgx_status_t create_vault_file(char * path, char* password, size_t len)
{
	size_t sealed_size = DEFAULT_SEALED_SIZE;
	uint8_t sealed_data[DEFAULT_SEALED_SIZE];
	sgx_sha256_hash_t hash;
	uint8_t master_key[16], iv[SIZE_AES_IV];
	uint8_t encrypted[44];
	sgx_aes_gcm_128bit_tag_t out_mac;
	sgx_status_t sgx_res;
	uint8_t result;
	get_sha256_hash(password, len, &hash);

	sgx_read_rand(master_key, 16);
	sgx_read_rand(iv, SIZE_AES_IV);
	sgx_res = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*)hash, master_key, 16, encrypted, iv, SIZE_AES_IV, NULL, 0, &out_mac);
	if (sgx_res)
		return sgx_res;//Error
	memcpy(encrypted + 16, iv, SIZE_AES_IV);
	memcpy(encrypted + 28, out_mac, 16);
	memcpy(main_key, master_key, 16);
	sgx_res = seal_ex(encrypted, 44, sealed_data, sealed_size, &sealed_size);
	if (sgx_res)
		return sgx_res;
	encalve_write_file(&result, path, (char *)sealed_data, sealed_size);
	CHECK_RESULT(result)
		return SGX_SUCCESS;
}
/* load_vault_from_file
* Purpose: This function is used to perform the operation of loading a vault file
*
* Paramters:
*      path - [IN] The Path for the vault file
*      password - [IN] The password used to decrypt the vault file
*      len - [IN] Length of the password in bytes

* Return Value:
*      If the function fails from any reason, the matching erroe code is returned.
*/
sgx_status_t load_vault_from_file(char * path, char* password, size_t len)
{
	uint8_t sealed_data[DEFAULT_SEALED_SIZE];
	uint8_t result;
	sgx_sha256_hash_t hash;
	uint8_t decrypted[DEFAULT_DECRYPTED_KEY_SIZE];
	uint8_t master_key[16], iv[SIZE_AES_IV];
	sgx_aes_gcm_128bit_tag_t old_mac;
	sgx_status_t sgx_res;
	encalve_read_file(&result, path, (char *)sealed_data, DEFAULT_SEALED_SIZE, NULL);
	CHECK_RESULT(result)
		get_sha256_hash(password, len, &hash);
	sgx_res = unseal(sealed_data, DEFAULT_SEALED_SIZE, decrypted, DEFAULT_DECRYPTED_KEY_SIZE);
	if (sgx_res)
		return sgx_res;
	memcpy(iv, decrypted + 16, SIZE_AES_IV);
	memcpy(old_mac, decrypted + 28, 16);
	sgx_res = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t*)hash, decrypted, 16, master_key, iv, SIZE_AES_IV, NULL, 0, &old_mac);
	if (sgx_res)
		return sgx_res;
	memcpy(main_key, master_key, 16);
	return SGX_SUCCESS;
}
/* enclave_close_vault
* Purpose: This function is used to close the current vault
*/
void enclave_close_vault()
{
	for (int i = 0; i < 16; i++)
		main_key[i] = NULL;
}
#pragma endregion

#pragma region 	File Functions
/* enclave_encrypt_file
* Purpose: This function is used to perform the encryption of a file
*
* Paramters:
*      path - [IN] The Path for the file
*      new_path - [IN] The Path for the encrypted file to be created
*      file_password - [IN] The password used to encrypt the file
*      len - [IN] Length of the password in bytes

* Return Value:
*      If the function fails from any reason, the matching erroe code is returned.
*/
sgx_status_t enclave_encrypt_file(char * path, char *new_path, char * file_password, size_t len)
{
	sgx_sha256_hash_t file_hash;
	uint8_t encrypted_hash[SHA_256_HASH_SIZE];
	sgx_sha_state_handle_t file_hash_handle;
	sgx_sha256_hash_t password_hash;
	uint8_t key_encrypt_IV[SIZE_AES_IV], hash_encrypt_IV[SIZE_AES_IV];
	uint8_t file_key[16];
	sgx_aes_gcm_128bit_tag_t hash_encrypt_out_mac, key_encrypt_out_mac;
	uint8_t IO_result;
	size_t size_input;
	bool finsihed_reading_file = false;
	uint8_t part_from_file_input[SIZE_AES_CTR_BLOCK_BYTE], part_cipher_text[SIZE_AES_CTR_BLOCK_BYTE], nounce_counter[SIZE_AES_CTR_BLOCK_BYTE];

	sgx_sha256_init(&file_hash_handle);
	get_sha256_hash(file_password, len, &password_hash);

	sgx_read_rand(key_encrypt_IV, SIZE_AES_IV);
	sgx_read_rand(hash_encrypt_IV, SIZE_AES_IV);
	sgx_read_rand(nounce_counter, SIZE_AES_CTR_BLOCK_BYTE);

	sgx_status_t res = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*)password_hash, main_key, 16, file_key, key_encrypt_IV, SIZE_AES_IV, NULL, 0, &key_encrypt_out_mac);
	if (res)
		return res;//Error

	encalve_write_end_of_open_file(&IO_result, new_path, NULL, 0, 0);
	CHECK_RESULT(IO_result)
		encalve_write_end_of_open_file(&IO_result, new_path, (char *)key_encrypt_IV, SIZE_AES_IV, 1);
	CHECK_RESULT(IO_result)
		encalve_write_end_of_open_file(&IO_result, new_path, (char *)hash_encrypt_IV, SIZE_AES_IV, 1);
	CHECK_RESULT(IO_result)
		encalve_write_end_of_open_file(&IO_result, new_path, (char *)key_encrypt_out_mac, 16, 1);
	CHECK_RESULT(IO_result)
		encalve_write_end_of_open_file(&IO_result, new_path, (char *)hash_encrypt_out_mac, 16, 1);
	CHECK_RESULT(IO_result)
		encalve_write_end_of_open_file(&IO_result, new_path, (char *)file_hash, SHA_256_HASH_SIZE, 1);
	CHECK_RESULT(IO_result)
		encalve_write_end_of_open_file(&IO_result, new_path, (char *)nounce_counter, SIZE_AES_CTR_BLOCK_BYTE, 1);
	CHECK_RESULT(IO_result)
		encalve_read_part_open_file(&IO_result, path, NULL, 0, &size_input, 0);
	CHECK_RESULT(IO_result)
		do
		{

			encalve_read_part_open_file(&IO_result, path, (char *)part_from_file_input, SIZE_AES_CTR_BLOCK_BYTE, &size_input, 1);
			CHECK_RESULT(IO_result)
				sgx_sha256_update((uint8_t*)part_from_file_input, size_input, file_hash_handle);

			if (size_input != 0)
			{
				if (size_input < SIZE_AES_CTR_BLOCK_BYTE)
					finsihed_reading_file = true;
				sgx_aes_ctr_encrypt((sgx_aes_gcm_128bit_key_t*)file_key, part_from_file_input, size_input, nounce_counter, 16, part_cipher_text);

				encalve_write_end_of_open_file(&IO_result, new_path, (char *)part_cipher_text, size_input, 1);
				CHECK_RESULT(IO_result)
			}
			else
				finsihed_reading_file = true;

		} while (!finsihed_reading_file);
		encalve_read_part_open_file(&IO_result, path, NULL, 0, &size_input, 2);
		CHECK_RESULT(IO_result)
			sgx_sha256_get_hash(file_hash_handle, (sgx_sha256_hash_t*)file_hash);
		sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*)main_key, file_hash, SHA_256_HASH_SIZE, encrypted_hash, hash_encrypt_IV, SIZE_AES_IV, NULL, 0, &hash_encrypt_out_mac);
		encalve_write_end_of_open_file(&IO_result, new_path, NULL, SIZE_AES_IV * 2 + 16, 3);
		CHECK_RESULT(IO_result)
			encalve_write_end_of_open_file(&IO_result, new_path, (char *)hash_encrypt_out_mac, 16, 1);
		CHECK_RESULT(IO_result)
			encalve_write_end_of_open_file(&IO_result, new_path, (char *)encrypted_hash, SHA_256_HASH_SIZE, 1);
		CHECK_RESULT(IO_result)
			encalve_write_end_of_open_file(&IO_result, new_path, NULL, 0, 2);
		CHECK_RESULT(IO_result)

			return SGX_SUCCESS;
}
/* enclave_decrypt_file
* Purpose: This function is used to perform the decryption of a file
*
* Paramters:
*      path - [IN] The Path for the encrypted
*      new_path - [IN] The Path for the decrypted file to be created
*      file_password - [IN] The password used to encrypt the file
*      len - [IN] Length of the password in bytes

* Return Value:
*      If the function fails from any reason, the matching erroe code is returned.
*/
sgx_status_t enclave_decrypt_file(char * path, char *new_path, char * file_password, size_t len)
{

	sgx_sha256_hash_t plain_file_hash;
	sgx_sha_state_handle_t plain_hash_handle;
	size_t size_input;
	uint8_t IO_result;
	sgx_sha256_hash_t file_password_hash;
	uint8_t key_encrypt_IV[SIZE_AES_IV], hash_encrypt_IV[SIZE_AES_IV];
	uint8_t file_key[16], encrypted_hash[SHA_256_HASH_SIZE], decrypted_hash[SHA_256_HASH_SIZE];
	sgx_aes_gcm_128bit_tag_t  hash_encrypt_out_mac, key_encrypt_out_mac, temp_out_mac;
	sgx_status_t sgx_res;
	bool finsihed_reading_file = false;
	uint8_t part_from_file_input[SIZE_AES_CTR_BLOCK_BYTE];
	uint8_t part_plain_text[SIZE_AES_CTR_BLOCK_BYTE];
	uint8_t nounce_counter_file_encrypt[SIZE_AES_CTR_BLOCK_BYTE];

	sgx_sha256_init(&plain_hash_handle);


	get_sha256_hash(file_password, len, &file_password_hash);

	encalve_read_part_open_file(&IO_result, path, NULL, 0, &size_input, 0);
	CHECK_RESULT(IO_result)
		encalve_read_part_open_file(&IO_result, path, (char*)key_encrypt_IV, SIZE_AES_IV, &size_input, 1);
	CHECK_RESULT(IO_result)
		encalve_read_part_open_file(&IO_result, path, (char*)hash_encrypt_IV, SIZE_AES_IV, &size_input, 1);
	CHECK_RESULT(IO_result)
		encalve_read_part_open_file(&IO_result, path, (char*)key_encrypt_out_mac, 16, &size_input, 1);
	CHECK_RESULT(IO_result)
		encalve_read_part_open_file(&IO_result, path, (char*)hash_encrypt_out_mac, 16, &size_input, 1);
	CHECK_RESULT(IO_result)
		encalve_read_part_open_file(&IO_result, path, (char*)encrypted_hash, SHA_256_HASH_SIZE, &size_input, 1);
	CHECK_RESULT(IO_result)


		sgx_res = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t*)main_key, encrypted_hash, SHA_256_HASH_SIZE, decrypted_hash, hash_encrypt_IV, SIZE_AES_IV, NULL, 0, &hash_encrypt_out_mac);
	if (sgx_res)
		return sgx_res;//Error
	sgx_res = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*)file_password_hash, main_key, 16, file_key, key_encrypt_IV, SIZE_AES_IV, NULL, 0, &temp_out_mac);
	if (sgx_res)
		return sgx_res;//Error
	if (memcmp(key_encrypt_out_mac, temp_out_mac, 16))
		return SGX_ERROR_MAC_MISMATCH;

	encalve_read_part_open_file(&IO_result, path, (char *)nounce_counter_file_encrypt, SIZE_AES_CTR_BLOCK_BYTE, &size_input, 1);
	CHECK_RESULT(IO_result)
		encalve_write_end_of_open_file(&IO_result, new_path, NULL, 0, 0);
	CHECK_RESULT(IO_result)
		do
		{

			encalve_read_part_open_file(&IO_result, path, (char *)part_from_file_input, SIZE_AES_CTR_BLOCK_BYTE, &size_input, 1);
			CHECK_RESULT(IO_result)
				if (size_input != 0)
				{
					if (size_input < SIZE_AES_CTR_BLOCK_BYTE)
						finsihed_reading_file = true;
					sgx_aes_ctr_decrypt((sgx_aes_gcm_128bit_key_t*)file_key, part_from_file_input, size_input, nounce_counter_file_encrypt, 16, part_plain_text);
					encalve_write_end_of_open_file(&IO_result, new_path, (char *)part_plain_text, size_input, 1);
					CHECK_RESULT(IO_result)
						sgx_sha256_update((uint8_t*)part_plain_text, size_input, plain_hash_handle);

				}
				else
					finsihed_reading_file = true;

		} while (!finsihed_reading_file);
		encalve_read_part_open_file(&IO_result, path, NULL, 0, &size_input, 2);
		CHECK_RESULT(IO_result)
			sgx_sha256_get_hash(plain_hash_handle, (sgx_sha256_hash_t*)plain_file_hash);

		if (memcmp(plain_file_hash, decrypted_hash, SHA_256_HASH_SIZE))
		{
			encalve_write_end_of_open_file(&IO_result, new_path, NULL, 0, 4);
			CHECK_RESULT(IO_result)
				return SGX_ERROR_MAC_MISMATCH;
		}
		encalve_write_end_of_open_file(&IO_result, new_path, NULL, 0, 2);
		CHECK_RESULT(IO_result)
			return SGX_SUCCESS;
}
#pragma endregion

//Other

/* get_sha256_hash
* Purpose: This function is used to get sha256_hash from a simple password
*
* Paramters:
*      password - [IN] The password from which to derive the hash
*      data_size - [IN] Length of the password in bytes
*      result - [OUT] The derived hash
*/
void get_sha256_hash(char * password, size_t len, sgx_sha256_hash_t* result)
{
	sgx_sha_state_handle_t handle;
	sgx_sha256_init(&handle);
	sgx_sha256_update((uint8_t*)password, len, handle);
	sgx_sha256_get_hash(handle, result);
}


