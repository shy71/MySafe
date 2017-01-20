#include <iostream>
#include <tchar.h>
#include <string.h>
#include "FileValut.h"
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"


#define ENCLAVE_FILE _T("Enclave.signed.dll")

void FileValut::create_enclave()
{
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_SUCCESS;
	int updated = 0;
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) 
		throw "Enclave couldn't open!\n Error code: " + ret;
}
FileValut::FileValut(char * path, char * mater_password)
{

}
