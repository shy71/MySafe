#pragma once
#include<string>
#include<fstream>
using namespace std;

struct FileValut
{
	uint64_t eid;
	void create_enclave();
	string last_error_msg;
public:
	FileValut();
	FileValut(char * path, char * master_password);
	FileValut(char * path, char * master_password, bool is_new_valut);
	void load_valut(char * path, char * master_password) 
	{
		string shy;
		shy = "shy";
	}
	void encrypt_file(char * path, char * user_password);
	void decrypt_file(char * path, char * user_password);
	void changer_user_password(char * path, char * old_password, char * new_password);
	void SetLastErrorMessage(const char * error) {}
};
