#pragma once
#include<string>
#include<fstream>
#include "sgx_urts.h"

using namespace std;

class FileVault
{
	//Variables
	sgx_enclave_id_t eid;
	bool vault_open = false;
	void create_enclave();
	string last_error_msg;
	sgx_status_t res;
	bool middle_of_process = false;

	//Functions

	//Constructor
	FileVault();

	//Close the enclave
	void close_enclave();
public:
	//Public variables

	//The Percentage of the current process
	double process_percentage;


	//Destructor
	~FileVault();


	//Static Functions

	//Get the File Vault object(or create it)
	static FileVault* getFileVault();

	//Delete the File Vault object
	static void deleteFileVault();


	//Vault Functions

	//Create a new vault file
	void create_vault(char * path, char * master_password);

	//Load a vault from a vault file
	void load_vault(char * path, char * master_password);

	//Close the current vault
	void close_vault();

	//Check wheter the vault is open right now
	bool is_vault_open();


	//Files Function

	//Encrypt a file
	void encrypt_file(char * path, char* new_path, char * file_password, bool delete_original);

	//Decrypt a file
	void decrypt_file(char * path, char* new_path, char * file_password, bool delete_encrypted);


	//Other Functions

	//Set the last_error_msg
	void SetLastErrorMessage(const char * error);
	string GetLastErrorMessage();
};
