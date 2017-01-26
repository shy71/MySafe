#include<fstream>
#include<iostream>
#include "FileManger.h"
#include "FileVault.h"
using namespace std;
void my_print3(char* str, size_t len)
{
	for (int i = 0; i < len; i++)
		cout << std::hex << ((int)((uint8_t)str[i])) << ",";
	cout << endl << endl;
}
void FileManger::write_file(char * path, char* buffer, size_t size)
{
	std::ofstream file;
	file.open(path, ios_base::binary);
	if (!file.is_open())
		throw "File wasn't open";
	file.write(buffer, size);
	file.close();
}
void FileManger::encalve_write_end_of_open_file(char * path, char* buffer, size_t size,int call_type)
{
	static 	std::ofstream file;
	if (call_type ==0)
	{
		if(file.is_open())
			throw "You can't open when a file is already opened";

		file.open(path, ios_base::binary);
		if (!file.is_open())
			throw "File wasn't open";
	}
	else if (call_type == 1)
	{
		if (!file.is_open())
			throw "File wasn't open";
		file.write(buffer, size);
	}
	else if (call_type == 2)
	{
		if (!file.is_open())
			throw "File wasn't open";
		file.close();
	}
	else if (call_type == 3)
	{
		if (!file.is_open())
			throw "File wasn't open";
		file.seekp(size, ios::beg);
	}
	else if (call_type == 4)
	{
		if (!file.is_open())
			throw "File wasn't open";
		file.close();
		file.open(path, ios_base::binary | ios::trunc);
		file.close();
		remove(path);
	}
}
int FileManger::getFileSize(const char * path)
{
	ifstream mySource;
	mySource.open(path, ios_base::binary);
	mySource.seekg(0, ios_base::end);
	int size = mySource.tellg();
	mySource.close();
	return size;
}
void FileManger::read_file(char * path, char* buffer, size_t size, size_t *actual_len)
{
	int fileSize = getFileSize(path);
	if (fileSize < size)
		if (actual_len == NULL)
		{
			size = fileSize;
		}
		else
		{
			*actual_len = fileSize;
			size = fileSize;
		}
	std::ifstream file;
	file.open(path, ios_base::binary);
	if (!file.is_open())
		throw "File wasn't open";
	file.read(buffer, size);
	file.close();

}
void FileManger::read_part_open_file(char * path, char* buffer, size_t size, size_t *actual_len,int call_type)
{
	static int fileSize;
	static int counter;
	static std::ifstream file;

	if (call_type == 0)
	{
		file.open(path, ios_base::binary);
		if (!file.is_open())
			throw "File wasn't open";
		fileSize = getFileSize(path);
		counter = 0;
		FileVault::getFileVault()->process_percentage = 0;
	}
	else if (call_type == 2)
	{
		counter = 0;
		fileSize = 0;
		if (!file.is_open())
			throw "File wasn't open";
		file.close();
		FileVault::getFileVault()->process_percentage = 99.9;
	}
	else if (call_type == 1)
	{
		if (!file.is_open())
			throw "File wasn't open";
		if (fileSize < counter + size)
		{
			if (actual_len != NULL)
				*actual_len = fileSize - counter;
		}
		else
			if (actual_len != NULL)
				*actual_len = size;
		file.read(buffer, size);
		counter += *actual_len;
		FileVault::getFileVault()->process_percentage = ((double)counter /(double) fileSize)*100;
	}

}


