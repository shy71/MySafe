#pragma once
#include<string>
#include<fstream>
#include "sgx_urts.h"

using namespace std;

class FileVault
{
	sgx_enclave_id_t eid;
	bool valut_open=false;
	void create_enclave();
	string last_error_msg;
	sgx_status_t res;
	FileVault();
	bool middle_of_process=false;
public:
	static FileVault* getFileVault();
	static void deleteFileVault();
	~FileVault();
	bool is_vault_open();
	void create_valut(char * path, char * master_password);
	void close_enclave();
	void load_valut(char * path, char * master_password);
	void close_valut();
	void encrypt_file(char * path, char* new_path, char * file_password,bool delete_original);
	void decrypt_file(char * path, char* new_path, char * file_password,bool delete_encrypted);
	void changer_user_password(char * path, char * old_password, char * new_password);
	void SetLastErrorMessage(const char * error);
	string GetLastErrorMessage();
	double process_percentage;

	//int get_precentege();



};
