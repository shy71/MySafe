#pragma once

#include<fstream>

using namespace std;

class FileManger
{
public:
	static void write_file(char * path, char* buffer, size_t size);
	static void encalve_write_end_of_open_file(char * path, char* buffer, size_t size,int call_type);

	static int getFileSize(const char *add);
	static void read_file(char * path, char* buffer, size_t size, size_t *actaul_len);
	static void read_part_open_file(char * path, char* buffer, size_t size, size_t *actaul_len,int call_type);

};