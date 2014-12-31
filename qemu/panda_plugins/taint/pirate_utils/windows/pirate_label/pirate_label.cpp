// pirate_label.cpp : Defines the entry point for the console application.
//

//#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>

#include "..\\pirate_mark.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void usage() {
	printf("Usage:\n");
	printf("pirate_label <file> <label> <start_offset> <region_size> <chunk_size>\n");
	printf("This utility enables labeling every byte of <file> with configurable labels.\n");
	printf("\t <file> = full path to file to be labeled\n");
	printf("\t <label> = label as an int\n");
	printf("\t <start_offset> = start labeling at given offset\n");
	printf("\t <region_size> = length of region to label (-1 = whole file)\n");
	printf("\t <chunk_size> = label the file in chunks (i.e. labels are chunked for each <chunk_size> bytes)\n");
	printf("\t\t NB: chunk_size must be <= 4096 bytes (and, of course, <= <region_size>).\n");
	printf("\t\t NB: chunk_size = -1 means no splitting (single label of <label>).\n");
}

//mz match block size
#define BUFFER_SIZE 4096
char file_buffer[BUFFER_SIZE];

int main(int argc, char* argv[])
{
	char *file_name;
	long label = 0;
	long start_offset = 0;
	long region_size = 0;
	long chunk_size = 0;
	HANDLE hFile;
	DWORD fileSizeLow, fileSizeHigh;
	DWORD ret;
	DWORD bytes_read = 0;
	DWORD bytes_written = 0;
	DWORD bytes_to_read = 0;
	int pos_label = 0;
	int single_label = 0;

	if (argc != 6) {
		usage();
		exit(1);
	}

	file_name = argv[1];
	label = atol(argv[2]);
	start_offset = atol(argv[3]);
	region_size = atol(argv[4]);
	chunk_size = atol(argv[5]);

	hFile = CreateFileA(file_name, 
					    GENERIC_READ | GENERIC_WRITE,
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
		printf("start offset invalid\n");
		CloseHandle(hFile);
		exit(4);
	}
	//mz check region_size
	if (region_size == -1) {
		region_size = fileSizeLow - start_offset;
	} else {
		if (start_offset + region_size >= (long)fileSizeLow || region_size <= 0) {
			printf("region_size invalid\n");
			CloseHandle(hFile);
			exit(4);
		}
	}

	ret = SetFilePointer(hFile, start_offset, NULL, FILE_BEGIN);
	if (ret < 0) {
		printf("SetFilePointer() failed: %x\n", GetLastError());
		CloseHandle(hFile);
		exit(5);
	}

	//mz max possible
	bytes_to_read = BUFFER_SIZE;

	if (chunk_size == -1) {
		single_label = 1;
	} 
	else if (chunk_size == 1) {
		pos_label = 1;
	}
	else {
		if (chunk_size <= 0 || chunk_size > region_size || chunk_size > BUFFER_SIZE) {
			printf("chunk_size invalid\n");
			CloseHandle(hFile);
			exit(5);
		}
		bytes_to_read = chunk_size;
	}

	//mz if single_label or pos_label, make sure we don't over-read
	bytes_to_read = (region_size < bytes_to_read) ? region_size : bytes_to_read;

	while ( (region_size > 0) && ReadFile(hFile, &file_buffer[0], bytes_to_read, &bytes_read, NULL) ) {
		//identity(&file_buffer[0], bytes_read);
		if (pos_label) {
			vm_label_buffer_pos(&file_buffer[0], bytes_read, start_offset);
		}
		else if (single_label) {
			vm_label_buffer(&file_buffer[0], bytes_read, label); 
		}
		else {
            // Else, chunk label.  Label the chunk with the starting offset of the chunk
			vm_label_buffer(&file_buffer[0], bytes_read, start_offset);
		}

		ret = SetFilePointer(hFile, (0 - bytes_read), NULL, FILE_CURRENT);
		if (ret < 0) {
			printf("SetFilePointer() failed: %x\n", GetLastError());
			CloseHandle(hFile);
			exit(6);
		}

		WriteFile(hFile, &file_buffer[0], bytes_read, &bytes_written, NULL);
		if (bytes_written != bytes_read) {
			printf("Write failed: %x\n", GetLastError());
			CloseHandle(hFile);
			exit(7);
		}

		start_offset += bytes_read;
		region_size -= bytes_read;

		//mz make sure to adjust amount to read here as well
		if (pos_label || single_label) {
			bytes_to_read = (region_size > BUFFER_SIZE) ? BUFFER_SIZE : region_size;
		}
		else {
			bytes_to_read = (region_size > chunk_size) ? chunk_size : region_size;
		}
	}

	CloseHandle(hFile);

	vm_guest_util_done();

	printf("Completed successfully\n");

	return 0;
}

