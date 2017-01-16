#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include<fstream>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

#define ENCLAVE_FILE _T("Enclave.signed.dll")
#define MAX_BUF_LEN 100
int main()
{

	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	char buffer[MAX_BUF_LEN] = "Hello World!";
	char buffer2[600];
	// Create the Enclave with above launch token.
	if (true)
	{
		std::ifstream myfile1;
		myfile1.open("token.txt");
		myfile1.read((char *)&token, 1024);
		myfile1.close();
	}
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated,
		&eid, NULL);
	if (false)
	{
		std::ofstream myfile1;
		myfile1.open("token.txt");
		myfile1.write((char *)&token, 1024);
		myfile1.close();
	}
	printf("%s", buffer2);
	if (ret != SGX_SUCCESS) {
		printf("App: error %#x, failed to create enclave.\n", ret);
		return -1;
	}
	int size = 0;
	// A bunch of Enclave calls (ECALL) will happen here.
	if (true)
	{
		std::ifstream myfile;
		myfile.open("example.txt");
		myfile.read(buffer2, 580);
		myfile.close();
	}
	trySeal(eid,&size, buffer2, 580,false);
	if (false)
	{
		std::ofstream myfile;
		myfile.open("example.txt");
		myfile.write(buffer2, 580);
		myfile.close();
	}
	printf("%s", buffer2);
	// Destroy the enclave when all Enclave calls finished.
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	return 0;
}