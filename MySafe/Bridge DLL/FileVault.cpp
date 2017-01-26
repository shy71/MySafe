#include <tchar.h>
#include <string.h>
#include<iostream>
#include "FileVault.h"
#include "Enclave_u.h"
#include "FileManger.h"
#include "sgx_urts.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"


#define ENCLAVE_FILE _T("Enclave.signed.dll")
//int precntege_of_encryption;
//int FileVault::get_precentege()
//{
//	return precntege_of_encryption;
//}
static FileVault* obj;
FileVault::~FileVault()
{
	close_valut();
	close_enclave();
}
FileVault* FileVault::getFileVault()
{
	if (obj == NULL)
	{
		obj = new FileVault();
		obj->create_enclave();
	}
	return obj;
}
void  FileVault::deleteFileVault()
{
	delete obj;
	obj = NULL;
}
void FileVault::close_enclave()
{
	sgx_destroy_enclave(eid);
	eid = NULL;
}
char * error_code_to_string( int error)
{
	switch (error)
	{
	case SGX_SUCCESS:
		return "SGX SUCESS!";
		break;
	case SGX_ERROR_OUT_OF_MEMORY:
		return "SGX Error: Out of Memory - Hint: Buffer is to small.";
		break;
	case SGX_ERROR_MAC_MISMATCH:
		return "SGX Error: Mac Mismatch - Hint: Wrong password,file,computer or vault.";
		break;
	case SGX_ERROR_FILE_BAD_STATUS:
		return "SGX Error: File Bad Status - Hint: Make sure the file is closed.";
		break;
	case SGX_ERROR_INVALID_PARAMETER:
		return "SGX Error: Invalid Parameter";
		break;
	case SGX_ERROR_UNEXPECTED:
	default:
		return "SGX Error: Unexpected.";
		break;
	}
}
exception* make_error_exception(char *operation, int error_number)
{
	/*char error[200];
	strcpy_s(error,20, operation);
	strcat_s(error, 25," -SGX Enclave Error - ");
	strcat_s(error, strlen(error_code_to_string(error_number)), error_code_to_string(error_number));*/
	encalve_write_end_of_open_file(NULL, NULL, 0, 2);
	encalve_read_part_open_file(NULL, NULL, 0, NULL,2);

	return new exception(error_code_to_string(error_number));
}
void FileVault::create_enclave()
{
	sgx_enclave_id_t eid;
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_SUCCESS;
	int updated = 0;
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret)
		throw make_error_exception("Create Enclave(SGX)", ret);
	this->eid = eid;
}
void FileVault::create_valut(char * path, char * master_password)
{
	if (valut_open)
		throw "You can'thve two opened vault at the same time";
	create_valut_file(eid, &res, path, master_password, strlen(master_password));
	if (res)
		throw make_error_exception("Create Vault", res);
	valut_open = true;

}
void FileVault::close_valut()
{
	enclave_close_valut(eid);
	valut_open = false;
}
void FileVault::load_valut(char * path, char * master_password)
{
	if (valut_open)
		throw "You can't have two opened vault at the same time";
	load_valut_from_file(eid, &res, path, master_password, strlen(master_password));
	if (res)
		throw make_error_exception("Load Vault", res);
	valut_open = true;
}
FileVault::FileVault() {}
void FileVault::encrypt_file(char * path,char* new_path,char * file_password)
{
	if (middle_of_process)
		throw "File Vault is in the middle of anther process! Please wait until it is over!";
	if (!valut_open)
		throw "You can't encrypt files before you load a vault!";
	middle_of_process = true;
	enclave_encrypt_file(eid, &res, path,new_path, file_password, strlen(file_password));
	middle_of_process = false;
	if (res)
		throw make_error_exception("Encrypt File", res);
}
void FileVault::decrypt_file(char * path, char* new_path, char * file_password)
{
	if (middle_of_process)
		throw "File Vault is in the middle of anther process! Please wait until it is over!";
	if (!valut_open)
		throw "You can't decrypt files before you load a vault!";
	middle_of_process = true;
	enclave_decrypt_file(eid, &res, path, new_path, file_password, strlen(file_password));
	middle_of_process = false;
	if (res)
		throw make_error_exception("Decrypt File", res);
}
void FileVault::changer_user_password(char * path, char * old_password, char * new_password) {}
void FileVault::SetLastErrorMessage(const char * error)
{
	last_error_msg = error;
}
string FileVault::GetLastErrorMessage()
{
	return last_error_msg;
}
uint8_t encalve_write_file(char *path, char* buffer, size_t len)
{
	try
	{
		FileManger::write_file(path, buffer, len);
	}
	catch (char*)
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
	catch (char* )
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
	catch (char* )
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
	catch (char* )
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
	catch (char* )
	{
		return;
	}
	return;
}
bool FileVault::is_vault_open() { return valut_open; }




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
	FileVault file;
	file.create_enclave();
	file.create_valut("try2", "shy71");
	system("pause");
	}
	else
	{
	FileVault file;
	file.create_enclave();
	file.load_valut("try2", "shy71");
	system("pause");
	}

	}*/
	try
	{
		/*FileVault file;
		file.create_enclave();
		file.load_valut("try2", "shy71");
		file.decrypt_file("TEXT.txt.ens", "text.txt", "123456");
		cout << "decrypted! Check text.txt" << endl;
		system("pause");*/
		/*int num;
		cin >> num;
		if (num == 1)
		{
			FileVault file;
			file.create_enclave();
			file.create_valut("try2", "shy71");
			system("pause");
		}
		else if (num == 2)
		{
			FileVault file;
			file.create_enclave();
			file.load_valut("try2", "shy71");
			file.encrypt_file("TEXT.txt", "TEXT.txt.ens", "123456");
			system("pause");
		}
		else if (num == 3)
		{
			FileVault file;
			file.create_enclave();
			file.load_valut("try2", "shy71");
			file.decrypt_file("TEXT.txt.ens", "text-2.txt", "123456");
			system("pause");
		}
		else if (num == 4)
		{
			FileVault file;
			file.create_enclave();
			file.load_valut("try2", "shy71");
			file.decrypt_file("TEXT.txt.ens", "text.shy", "123456");
			system("pause");
		}*/
	}
	catch (exception ex)
	{
		cout << ex.what() << endl;
	}
}