#pragma once
#include<string>
#include<fstream>
#include "sgx_urts.h"

using namespace std;

struct FileValut
{
	sgx_enclave_id_t eid;
	bool valut_open=false;
	void create_enclave();
	string last_error_msg;
	sgx_status_t res;
public:
	FileValut();
	~FileValut();
	bool is_vault_open();
	void create_valut(char * path, char * master_password);
	void close_enclave();
	void load_valut(char * path, char * master_password);
	void close_valut();
	void encrypt_file(char * path, char * file_password);
	void decrypt_file(char * path, char* newpath, char * file_password);
	void changer_user_password(char * path, char * old_password, char * new_password);
	void SetLastErrorMessage(const char * error);
	string GetLastErrorMessage();


};
