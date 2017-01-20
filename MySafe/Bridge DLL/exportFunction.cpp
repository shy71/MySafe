#include "FileValut.h"

//writes the functions written in lib into a dll file 
extern "C"
{
	//DISK FUNCTIONS:
	__declspec(dllexport) void load_valut(FileValut* THIS,char * path, char* master_password)
	{
		try
		{
			THIS->load_valut(path, master_password);
		}
		catch (exception ex)
		{
			THIS->SetLastErrorMessage(ex.what());
			throw ex;
		}
		catch (char* ex)
		{
			THIS->SetLastErrorMessage(ex);
			throw ex;
		}
	}
}