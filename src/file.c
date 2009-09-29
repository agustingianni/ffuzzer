#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gwar.h"
#include "utils.h"
#include "fuzzer.h"
#include "file.h"
#include "parser.h"

int
MapFile(char *filename, void **address)
{
	int fd;
	int flags = O_RDWR;
	struct stat st;
	
	fd = open(filename, flags);
	if(fd == -1)
	{
		perror("[!] map_file::open()");
		return -1;
	}
	else
	{
		if(fstat(fd, &st) == -1)
		{
			perror("[!] map_file::fstat()");
			close(fd);
			return -1;
		}
		else
		{
			if(S_ISREG(st.st_mode))
			{
				*address = mmap(0, st.st_size, PROT_READ | PROT_WRITE,
					MAP_SHARED, fd, 0);
					
				if(*address == MAP_FAILED)
				{
					perror("[!] map_file::mmap()");
					close(fd);
					return -1;
				}
			
				close(fd);
			}
			else
			{
				fprintf(stderr, "[!] %s Is not a regular file\n", filename);
				close(fd);
				return -1;
			}
		}
	}
	
	return st.st_size;
}

off_t
GetFileSize(char *filename)
{
	struct stat s;
	if(stat(filename, &s) == -1)
	{
		perror("[!] get_filesize:stat()");
		return 0;
	}
	
	return s.st_size;
}
