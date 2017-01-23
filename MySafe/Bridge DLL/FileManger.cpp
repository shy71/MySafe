#include<fstream>
#include<iostream>
#include "FileManger.h"

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
int FileManger::getFileSize(const char * path)
{
	ifstream mySource;
	mySource.open(path, ios_base::binary);
	mySource.seekg(0, ios_base::end);
	int size = mySource.tellg();
	mySource.close();
	return size;
}
void FileManger::read_file(char * path, char* buffer, size_t size,size_t *actual_len)
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


