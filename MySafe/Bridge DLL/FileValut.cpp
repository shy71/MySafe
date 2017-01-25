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

FileValut::~FileValut()
{
	close_valut();
	close_enclave();
}

void FileValut::close_enclave()
{
	sgx_destroy_enclave(eid);
	eid = NULL;
}

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
	if (valut_open)
		throw "You can'thve two opened vault at the same time";
	create_valut_file(eid, &res, path, master_password, strlen(master_password));
	valut_open = true;
	if (res)
		throw "Create Valut - Enclave Exception - " + (char)res;
}
void FileValut::close_valut()
{
	enclave_close_valut(eid);
	valut_open = false;
}
void FileValut::load_valut(char * path, char * master_password)
{
	if (valut_open)
		throw "You can'thve two opened vault at the same time";
	load_valut_from_file(eid, &res, path, master_password, strlen(master_password));
	valut_open = true;
	if (res)
		throw "Load Valut - Enclave Exception - " + (char)res;
}
FileValut::FileValut() {}
void FileValut::encrypt_file(char * path, char * file_password)
{
	if (!valut_open)
		throw "You can't encrypt files before you load a vault!";
	enclave_encrypt_file(eid, &res, path, file_password, strlen(file_password));
	if (res)
		throw "Encrypt File - Enclave Exception - " + (char)res;
}
void FileValut::decrypt_file(char * path, char* newpath, char * file_password)
{
	if (!valut_open)
		throw "You can't decrypt files before you load a vault!";
	enclave_decrypt_file(eid, &res, path, newpath, file_password, strlen(file_password));
	if (res)
		throw "Encrypt File - Enclave Exception - " + (char)res;
}
void FileValut::changer_user_password(char * path, char * old_password, char * new_password) {}
void FileValut::SetLastErrorMessage(const char * error)
{
	last_error_msg = error;
}
string FileValut::GetLastErrorMessage()
{
	return last_error_msg;
}
uint8_t encalve_write_file(char *path, char* buffer, size_t len)
{
	try
	{
		FileManger::write_file(path, buffer, len);
	}
	catch (char* error)
	{
		return 1;
	}
	return 0;
}
uint8_t encalve_write_end_of_open_file(char *path, char* buffer, size_t len,int call_type)
{
	try
	{
		FileManger::encalve_write_end_of_open_file(path, buffer, len, call_type);
	}
	catch (char* error)
	{
		return 1;
	}
	return 0;
}
uint8_t encalve_read_file(char *path, char* buffer, size_t len, size_t *actual_len)
{
	try
	{
		FileManger::read_file(path, buffer, len, actual_len);
	}
	catch (char* error)
	{
		return 1;
	}
	return 0;
}
uint8_t encalve_read_part_open_file(char *path, char* buffer, size_t len, size_t *actual_len,int call_type)
{
	try
	{
		FileManger::read_part_open_file(path, buffer, len, actual_len,call_type);
	}
	catch (char* error)
	{
		return 1;
	}
	return 0;
}
void encalve_file_size(char *path, size_t *size)
{
	try
	{
		*size = FileManger::getFileSize(path);
	}
	catch (char* error)
	{
		return;
	}
	return;
}
bool FileValut::is_vault_open() { return valut_open; }

void get_file_istream(char * path, uint8_t *pointer, uint32_t *size, uint32_t offset)
{
	*size = FileManger::getFileSize(path);
	ifstream *file = new ifstream;
	file->open(path, ios_base::binary);
	if (!file->is_open())
		throw "File wasn't open";
	if (offset != 0)
		file->seekg(offset);
	*pointer = (uint8_t)file;
}
void get_file_ostream(char * path, uint8_t *pointer)
{
	ofstream *file = new ofstream;
	file->open(path, ios_base::binary);
	if (!file->is_open())
		throw "File wasn't open";
	*pointer = (uint8_t)file;
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
	/*try
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

	}*/
	try
	{
		/*FileValut file;
		file.create_enclave();
		file.load_valut("try2", "shy71");
		file.decrypt_file("TEXT.txt.ens", "text.txt", "123456");
		cout << "decrypted! Check text.txt" << endl;
		system("pause");*/
		int num;
		cin >> num;
		if (num == 1)
		{
			FileValut file;
			file.create_enclave();
			file.create_valut("try2", "shy71");
			system("pause");
		}
		else if (num == 2)
		{
			FileValut file;
			file.create_enclave();
			file.load_valut("try2", "shy71");
			file.encrypt_file("TEXT.txt", "123456");
			system("pause");
		}
		else if (num == 3)
		{
			FileValut file;
			file.create_enclave();
			file.load_valut("try2", "shy71");
			file.decrypt_file("TEXT.txt.ens", "text-2.txt", "123456");
			system("pause");
		}
		else if (num == 4)
		{
			FileValut file;
			file.create_enclave();
			file.load_valut("try2", "shy71");
			file.decrypt_file("TEXT.txt.ens", "text.shy", "123456");
			system("pause");
		}
	}
	catch (exception ex)
	{
		cout << ex.what() << endl;
	}
}