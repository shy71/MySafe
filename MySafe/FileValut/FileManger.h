#pragma once

#include<fstream>

using namespace std;

class FileManger
{
public:
	void write_file(char * path, char* buffer, size_t size);
	int getFileSize(const char *add);
	void read_file(char * path, char* buffer, size_t size);
};