#pragma once

#include<fstream>

using namespace std;

class FileManger
{
public:
	static void write_file(char * path, char* buffer, size_t size);
	static int getFileSize(const char *add);
	static void read_file(char * path, char* buffer,size_t size, size_t *actaul_len);
};