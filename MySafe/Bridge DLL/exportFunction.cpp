#include "FileValut.h"
//writes the functions written in lib into a dll file 
extern "C"
{
	//DISK FUNCTIONS:
	__declspec(dllexport) void load_valut(FileValut* object,char * path, char* master_password)
	{
		try
		{
			object->load_valut(path, master_password);
		}
		catch (exception ex)
		{
			object->SetLastErrorMessage(ex.what());
			throw ex;
		}
		catch (char* ex)
		{
			object->SetLastErrorMessage(ex);
			throw ex;
		}
	}
}