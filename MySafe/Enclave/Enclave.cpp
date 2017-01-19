#include "Enclave_t.h"

#include "sgx_trts.h"
// sample_enclave.cpp
#include <string.h>


#include "sgx_tseal.h"
#define TEXT_LENGTH 20
void seal(uint8_t *data_buffer, size_t data_size,uint8_t *sealed_data,size_t buffer_size, size_t* actual_size)
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
	sgx_status_t res = sgx_seal_data(0, NULL,data_size, data_buffer, sealed_size, (sgx_sealed_data_t *)sealed_data_space);
	if (res)
	{
		*actual_size = -res;
		return;
	}
	*actual_size = sealed_size;
	memcpy(sealed_data, sealed_data_space, sealed_size);
}
void seal_ex(uint8_t *data_buffer, size_t data_size, uint8_t *sealed_data, size_t buffer_size, size_t* actual_size)
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
	sgx_attributes_t attr;
	attr.flags = SGX_FLAGS_PROVISION_KEY | SGX_FLAGS_LICENSE_KEY | SGX_FLAGS_INITTED |SGX_FLAGS_DEBUG | SGX_FLAGS_RESERVED;
	attr.xfrm = 0;
	sgx_status_t res = sgx_seal_data_ex(1, attr, NULL, NULL, NULL, data_size, data_buffer, sealed_size, (sgx_sealed_data_t *)sealed_data_space);
	//sgx_status_t res = sgx_seal_data(0, NULL, data_size, data_buffer, sealed_size, (sgx_sealed_data_t *)sealed_data_space);
		if (res)
		{
			*actual_size = -res;;
			return;
		}
	*actual_size = sealed_size;
	memcpy(sealed_data, sealed_data_space, sealed_size);
}
void unseal(uint8_t *sealed_data, size_t sealed_size,uint8_t *plain_data, size_t buffer_size, size_t* actual_size)
{
	uint8_t* sealed_space = new uint8_t[sealed_size];
	memcpy(sealed_space, sealed_data, sealed_size);
	*actual_size = sealed_space[0];
	uint32_t plain_data_size = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)sealed_space);
	if (plain_data_size == UINT32_MAX)
	{
		*actual_size = -1;
		return;//Error
	}
	else if (plain_data_size > buffer_size)
	{
		*actual_size = plain_data_size;
		return;//Error
	}
	uint8_t* plain_data_space = new uint8_t[plain_data_size];
	sgx_status_t res = sgx_unseal_data((sgx_sealed_data_t *)sealed_space, NULL, NULL, plain_data_space, &plain_data_size);
	if (res)
	{
		*actual_size =- res;
		return;//Error
	}
	*actual_size = plain_data_size;
	memcpy(plain_data, plain_data_space, plain_data_size);

}

//int trySeal(char *bufin,char *bufout, size_t len, int  encrypt)
//{
//	uint8_t *plaintext = new uint8_t[1000];
//	sgx_status_t res;
//	
//
//	uint32_t plain_size = TEXT_LENGTH;
//	char *text = new char[TEXT_LENGTH];
//	strncpy(text, "Sh133", TEXT_LENGTH);
//	sgx_attributes_t attr;
//	attr.flags = 0xfffffffffffffff3;
//	attr.xfrm = 0;
// 	// Do the test loop
//
//	/*res = sgx_seal_data_ex(1, attr, 0, 0xFFFFFFFF, NULL, TEXT_LENGTH,(uint8_t*) text, ciph_size,
//	(sgx_sealed_data_t *)sealed);*/
//	return -1;
//}
void foo(char *buf, size_t len)
{
	const char *secret = "Hello Enclave!";
	if (len > strlen(secret))
	{
		memcpy(buf, secret, strlen(secret) + 1);
	}
}
