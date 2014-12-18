// pirate_query.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <stdlib.h>

#include "..\\pirate_mark.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void usage() {
	printf("Usage:\n");
	printf("pirate_query <file> <start_offset> <end_offset>\n");
	printf("This utility enables querying taint on bytes in <file>.\n");
	printf("\t <file> = full path to file to be labeled\n");
	printf("\t <start_offset> = beginning of region to be queried (in bytes)\n");
	printf("\t <len> = number of bytes to be queried or -1 for 'end-of-file'\n");
}

//mz match block size
#define BUFFER_SIZE 4096
char file_buffer[BUFFER_SIZE];

int main(int argc, char* argv[])
{
	char *file_name;
	long start_offset = 0;
	long region_size = 0;
	long current_offset = 0;
	HANDLE hFile;
	DWORD fileSizeLow, fileSizeHigh;
	DWORD ret;
	DWORD bytes_read = 0;
	DWORD bytes_to_read = 0;

	if (argc != 4) {
		usage();
		exit(1);
	}

	file_name = argv[1];
	start_offset = atol(argv[2]);
	region_size = atol(argv[3]);

	hFile = CreateFileA(file_name, 
							  GENERIC_READ,
							  0,
							  NULL,
							  OPEN_EXISTING,
							  FILE_FLAG_SEQUENTIAL_SCAN,
							  NULL);
	
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Cannot open file %s: %x\n", file_name, GetLastError());
		exit(2);
	}
	
	fileSizeLow = GetFileSize(hFile, &fileSizeHigh);
	if (fileSizeHigh != 0) {
		printf("File too large.\n");
		CloseHandle(hFile);	
		exit(3);
	}
	if (fileSizeLow < 0) {
		printf("GetFileSize() failed: %x\n", GetLastError());
		CloseHandle(hFile);
		exit(3);
	}

	//mz check start offset
	if (start_offset >= (long)fileSizeLow || start_offset < 0) {
		printf("start offset (%d) invalid\n", start_offset);
		CloseHandle(hFile);
		exit(4);
	}
	//mz check region_size
	if (region_size == -1) {
		region_size = fileSizeLow - start_offset;
	} else {
		if (start_offset + region_size >= (long)fileSizeLow || region_size < 0) {
			printf("region_size (%d) invalid\n", region_size);
			CloseHandle(hFile);
			exit(4);
		}
	}

	printf("Will read %d bytes from file\n", region_size);

	ret = SetFilePointer(hFile, start_offset, NULL, FILE_BEGIN);
	if (ret < 0) {
		printf("SetFilePointer() failed: %x\n", GetLastError());
		CloseHandle(hFile);
		exit(5);
	}

	//mz we summarily assume that region_size > BUFFER_SIZE, which may not be correct
	bytes_to_read = (region_size > BUFFER_SIZE) ? BUFFER_SIZE : region_size;
	current_offset = start_offset;
	
	while ( (region_size > 0) && ReadFile(hFile, &file_buffer[0], bytes_to_read, &bytes_read, NULL)) {
		vm_query_buffer(&file_buffer[0], bytes_read, /*name=*/file_name, /*name_len=*/strlen(file_name), /*offset=*/current_offset);
		region_size -= bytes_read;
		current_offset += bytes_read;
		//mz make sure to adjust amount to read here as well
		bytes_to_read = (region_size > BUFFER_SIZE) ? BUFFER_SIZE : region_size;
	}

	CloseHandle(hFile);

	vm_guest_util_done();

	printf("Completed successfully.\n");

	return 0;
}

