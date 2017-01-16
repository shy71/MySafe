#include "Enclave_t.h"

#include "sgx_trts.h"
// sample_enclave.cpp
#include <string.h>


#include "sgx_tseal.h"
#define TEXT_LENGTH 20
int trySeal(char *buf, size_t len, int  encrypt)
{
	uint8_t *plaintext = new uint8_t[TEXT_LENGTH];
	sgx_status_t res;
	uint32_t ciph_size = sgx_calc_sealed_data_size(0, TEXT_LENGTH);
	uint8_t* sealed = new uint8_t[ciph_size];

	uint32_t plain_size = TEXT_LENGTH;
	char *text = new char[TEXT_LENGTH];
	strncpy(text, "Shy72", TEXT_LENGTH);
	sgx_attributes_t attr;
	attr.flags = 0xfffffffffffffff3;
	attr.xfrm = 0;
 	// Do the test loop


	if (encrypt)
	{
		res = sgx_seal_data(0, NULL, TEXT_LENGTH, (uint8_t*)text, ciph_size, (sgx_sealed_data_t *)sealed);
		if (res != SGX_SUCCESS) { memcpy(buf, "Seal error", TEXT_LENGTH); return 0; }
	memcpy(buf, sealed, ciph_size);
	}
	else
	{
		res = sgx_unseal_data((sgx_sealed_data_t *)sealed, NULL, NULL, plaintext, &plain_size);
		if (res != SGX_SUCCESS) { memcpy(buf, "unSeal error!", TEXT_LENGTH); return 0; }
		memcpy(buf, plaintext, plain_size);

	}
	/*res = sgx_seal_data_ex(1, attr, 0, 0xFFFFFFFF, NULL, TEXT_LENGTH,(uint8_t*) text, ciph_size,
	(sgx_sealed_data_t *)sealed);*/
	return ciph_size;
}
void foo(char *buf, size_t len)
{
	const char *secret = "Hello Enclave!";
	if (len > strlen(secret))
	{
		memcpy(buf, secret, strlen(secret) + 1);
	}
}