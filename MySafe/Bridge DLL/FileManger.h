#pragma once

#include<fstream>

using namespace std;

class FileManger
{
public:
	//Output Functions

	//Write file
	static void write_file(char * path, char* buffer, size_t size);

	/*Encalve Output opertions on file
	Call_type=0: open the file in the path for writing
	Call_type=1: write to the open file
	Call_type=2: close the open file
	Call_type=3: Go the offset size from the begining of the open file
	Call_type=4: close, clear and delete the open file
	*/
	static void encalve_write_end_of_open_file(char * path, char* buffer, size_t size, int call_type);


	//Input Functions

	//read file
	static void read_file(char * path, char* buffer, size_t size, size_t *actaul_len);

	/*Encalve Input opertions on file
	Call_type=0: open the file in the path for reading
	Call_type=1: read from the open file
	Call_type=2: close the open file
	*/
	static void read_part_open_file(char * path, char* buffer, size_t size, size_t *actaul_len, int call_type);

	// get File Size of the file
	static int get_file_size(const char *add);
};