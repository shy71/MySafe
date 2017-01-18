#include <iostream>
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
using namespace std;
void write_file(char * path, char* buffer, size_t size)
{
	std::ofstream file;
	file.open(path);
	file.write(buffer, size);
	file.close();
}
int getFileSize(const char *add) {
	ifstream mySource;
	mySource.open(add, ios_base::binary);
	mySource.seekg(0, ios_base::end);
	int size = mySource.tellg();
	mySource.close();
	return size;
}
void read_file(char * path, char* buffer, size_t size)
{
	int fileSize=getFileSize(path);
	if (fileSize > size)
		return;//Error
	std::ifstream file;
	file.open(path);
	file.read(buffer, fileSize);
	file.close();
}
sgx_enclave_id_t create_enclave()
{
	sgx_launch_token_t token = { 0 };
	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	int updated = 0;
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated,&eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("App: error %#x, failed to create enclave.\n", ret);
		return -1;
	}
	return eid;
}
int main()
{
	sgx_enclave_id_t enclave = create_enclave();
	int chosen=0;
	while(chosen!=3) 
	{
		cout << "seal: 1 \nunseal: 2" << endl;
		cin >> chosen;
		if (chosen == 1)
		{
			char str[500], path[100];
			uint8_t sealed_data[3000];
			size_t size = 3000;
			cout << "data:" << endl;
			cin.getline(str, 500);
			cin.getline(str, 500);
			cout << "file path:" << endl;
			cin.getline(path, 500);
			seal(enclave, (uint8_t*)str, strlen(str), sealed_data,size, &size);
			write_file(path, (char*)sealed_data, size);

		}
		if (chosen == 2)
		{
			char str[500], path[100];
			uint8_t sealed_data[3000];
			size_t size = 3000,text_size=500;
			cout << "file path:" << endl;
			cin.getline(path, 500);
			cin.getline(path, 500);
			read_file(path, (char*)sealed_data, size);
			unseal(enclave, sealed_data, size, (uint8_t*)str, text_size, &text_size);
			cout << "data:" << endl;
			cout << str << endl;
			system("pause");
		}
	}
	// Destroy the enclave when all Enclave calls finished.
	if (SGX_SUCCESS != sgx_destroy_enclave(enclave))
		return -1;
	return 0;
}