#include "FileVault.h"

extern "C"
{
#pragma region Get and Delete Functions
	__declspec(dllexport) FileVault* getFileVaultObj()
	{
		return FileVault::getFileVault();

	}
	__declspec(dllexport) void deleteFileVaultobj(FileVault*& obj)
	{
		FileVault::deleteFileVault();
		obj = NULL;
	}
#pragma endregion

#pragma region 	Vault Functions
	__declspec(dllexport) void create_vault(FileVault* obj, char * path, char* master_password)
	{
		try
		{
			obj->create_vault(path, master_password);
		}
		catch (exception* ex)
		{
			obj->SetLastErrorMessage(ex->what());
			throw ex;
		}
		catch (char* ex)
		{
			obj->SetLastErrorMessage(ex);
			throw ex;
		}
	}
	__declspec(dllexport) void load_vault(FileVault* obj, char * path, char* master_password)
	{
		try
		{
			obj->load_vault(path, master_password);
		}
		catch (exception* ex)
		{
			obj->SetLastErrorMessage(ex->what());
			throw ex;
		}
		catch (char* ex)
		{
			obj->SetLastErrorMessage(ex);
			throw ex;
		}
	}
	__declspec(dllexport) int is_vault_open(FileVault* obj)
	{
		try
		{
			return obj->is_vault_open();
		}
		catch (exception* ex)
		{
			obj->SetLastErrorMessage(ex->what());
			throw ex;
		}
		catch (char* ex)
		{
			obj->SetLastErrorMessage(ex);
			throw ex;
		}
	}
	__declspec(dllexport) void close_vault(FileVault* obj)
	{
		try
		{
			obj->close_vault();
		}
		catch (exception* ex)
		{
			obj->SetLastErrorMessage(ex->what());
			throw ex;
		}
		catch (char* ex)
		{
			obj->SetLastErrorMessage(ex);
			throw ex;
		}
	}
#pragma endregion

#pragma region 	Files Functions
	__declspec(dllexport) void encrypt_file(FileVault* obj, char * path, char * new_path, char * file_password, int delete_original)
	{
		try
		{
			obj->encrypt_file(path, new_path, file_password, (bool)delete_original);
		}
		catch (exception* ex)
		{
			obj->SetLastErrorMessage(ex->what());
			throw ex;
		}
		catch (char* ex)
		{
			obj->SetLastErrorMessage(ex);
			throw ex;
		}
	}
	__declspec(dllexport) void decrypt_file(FileVault* obj, char * path, char* new_path, char * file_password, int delete_encrypted)
	{
		try
		{
			obj->decrypt_file(path, new_path, file_password, delete_encrypted);
		}
		catch (exception* ex)
		{
			obj->SetLastErrorMessage(ex->what());
			throw ex;
		}
		catch (char* ex)
		{
			obj->SetLastErrorMessage(ex);
			throw ex;
		}
	}
	__declspec(dllexport) double get_precntege_of_process(FileVault* obj)
	{
		try
		{
			return obj->process_percentage;
		}
		catch (exception* ex)
		{
			obj->SetLastErrorMessage(ex->what());
			throw ex;
		}
		catch (char* ex)
		{
			obj->SetLastErrorMessage(ex);
			throw ex;
		}
	}
#pragma endregion

#pragma region 	Other Functions
	__declspec(dllexport) const char* GetLastFileVaultErrorMessage(FileVault* obj)
	{
		char* str = new char[200];
		strcpy_s(str, 200, obj->GetLastErrorMessage().c_str());
		return str;
	}
#pragma endregion
}