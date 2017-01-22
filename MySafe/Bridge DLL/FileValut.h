#pragma once
#include<string>
#include<fstream>
#include "sgx_urts.h"

using namespace std;

struct FileValut
{
	sgx_enclave_id_t eid;
	void create_enclave();
	string last_error_msg;
	sgx_status_t res;
public:
	FileValut();
	static FileValut* makeFileValutObject(char *path, char *mater_password);
	static FileValut* makeFileValutObject(char *path, char *mater_password, bool create_new);
	void create_valut(char * path, char * master_password);
	void load_valut(char * path, char * master_password);
	void encrypt_file(char * path, char * user_password);
	void decrypt_file(char * path, char * user_password);
	void changer_user_password(char * path, char * old_password, char * new_password);
	void SetLastErrorMessage(const char * error);

};
