#include <tchar.h>
#include <string.h>
#include<iostream>
#include "FileValut.h"
#include "Enclave_u.h"
#include "FileManger.h"
#include "sgx_urts.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"


#define ENCLAVE_FILE _T("Enclave.signed.dll")

FileValut* FileValut::makeFileValutObject(char * path, char* master_password)
{
	FileValut* fvalut = new FileValut();
	fvalut->create_enclave();
	fvalut->load_valut(path, master_password);
	return fvalut;
}

FileValut* FileValut::makeFileValutObject(char * path, char * master_password, bool create_new) { return NULL; }
void FileValut::create_enclave()
{
	sgx_enclave_id_t eid;
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_SUCCESS;
	int updated = 0;
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
		throw "Enclave couldn't open!\n Error code: " + ret;
	this->eid = eid;
}
void FileValut::create_valut(char * path, char * master_password)
{
	size_t selaed_size = 3000;
	uint8_t *sealed_data = new uint8_t[selaed_size];
	create_valut_file(eid, &res, master_password, strlen(master_password), sealed_data, selaed_size, &selaed_size);
	if (res)
		throw "Enclave Exception - " + (char)res;
	FileManger::write_file(path, (char *)sealed_data, selaed_size);
}
void FileValut::load_valut(char * path, char * master_password)
{
	size_t sealed_size = 3000;
	uint8_t *sealed_data = new uint8_t[sealed_size];
	FileManger::read_file(path, (char *)sealed_data, 3000);
	load_valut_from_file(eid, &res, master_password, strlen(master_password), sealed_data, sealed_size);
	if (res)
		throw "Enclave Exception - " + (char)res;

}
FileValut::FileValut() {}
void FileValut::encrypt_file(char * path, char * user_password) {}
void FileValut::decrypt_file(char * path, char * user_password) {}
void FileValut::changer_user_password(char * path, char * old_password, char * new_password) {}
void FileValut::SetLastErrorMessage(const char * error)
{
	last_error_msg = error;
}
void my_print(char* str, size_t len)
{
	for (int i = 0; i < len; i++)
		cout << std::hex << ((int)((uint8_t)str[i])) << ",";
	cout << endl << endl;
}
void my_print2(int num)
{
	cout << "-" << num << endl;
}
int main()
{
	try
	{
		int num;
		cin >> num;
		if (num)
		{
			FileValut file;
			file.create_enclave();
			file.create_valut("try2", "shy71");
			system("pause");
		}
		else
		{
			FileValut file;
			file.create_enclave();
			file.load_valut("try2", "shy71");
			system("pause");
		}

	}
	catch (exception ex)
	{
		cout << ex.what() << endl;
	}
}