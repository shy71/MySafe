#include "FileValut.h"
//writes the functions written in lib into a dll file 
extern "C"
{
	//DISK FUNCTIONS:
	__declspec(dllexport) FileValut* makeFileValutobj()
	{
		FileValut *obj = new FileValut();
		obj->create_enclave();
		return obj;
	}
	__declspec(dllexport) void deleteFileValutobj(FileValut*& obj)
	{
		if (obj != NULL)
			delete  obj;
		obj = NULL;
	}
	__declspec(dllexport) const char* GetLastFileValutErrorMessage(FileValut* obj)
	{
		const char* str = obj->GetLastErrorMessage().c_str();
		return str;
	}
	__declspec(dllexport) void create_valut(FileValut* obj, char * path, char* master_password)
	{
		try
		{
			obj->create_valut(path, master_password);
		}
		catch (exception ex)
		{
			obj->SetLastErrorMessage(ex.what());
			throw ex;
		}
		catch (char* ex)
		{
			obj->SetLastErrorMessage(ex);
			throw ex;
		}
	}
	__declspec(dllexport) void close_valut(FileValut* obj)
	{
		try
		{
			obj->close_valut();
		}
		catch (exception ex)
		{
			obj->SetLastErrorMessage(ex.what());
			throw ex;
		}
		catch (char* ex)
		{
			obj->SetLastErrorMessage(ex);
			throw ex;
		}
	}
	__declspec(dllexport) void load_valut(FileValut* obj,char * path, char* master_password)
	{
		try
		{
			obj->load_valut(path, master_password);
		}
		catch (exception ex)
		{
			obj->SetLastErrorMessage(ex.what());
			throw ex;
		}
		catch (char* ex)
		{
			obj->SetLastErrorMessage(ex);
			throw ex;
		}
	}
	__declspec(dllexport) void encrypt_file(FileValut* obj, char * path, char * file_password)
	{
		try
		{
			obj->encrypt_file(path, file_password);
		}
		catch (exception ex)
		{
			obj->SetLastErrorMessage(ex.what());
			throw ex;
		}
		catch (char* ex)
		{
			obj->SetLastErrorMessage(ex);
			throw ex;
		}
	}
	__declspec(dllexport) void decrypt_file(FileValut* obj, char * path,char* newpath, char * file_password)
	{
		try
		{
			obj->decrypt_file(path, newpath,file_password);
		}
		catch (exception ex)
		{
			obj->SetLastErrorMessage(ex.what());
			throw ex;
		}
		catch (char* ex)
		{
			obj->SetLastErrorMessage(ex);
			throw ex;
		}
	}
}