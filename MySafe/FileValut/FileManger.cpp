#include<fstream>
#include "FileManger.h"

using namespace std;

void FileManger::write_file(char * path, char* buffer, size_t size)
{
	std::ofstream file;
	file.open(path);
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
void FileManger::read_file(char * path, char* buffer, size_t size)
{
	int fileSize = getFileSize(path);
	if (fileSize > size)
		return;//Error
	std::ifstream file;
	file.open(path);
	file.read(buffer, fileSize);
	file.close();
}
