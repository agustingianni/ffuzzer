#ifdef BSD
 #undef _GNU_SOURCE
#else
 #define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "gwar.h"
#include "file.h"
#include "fuzzer.h"
#include "parser.h"
#include "mappings.h"

int
FreeMapList(struct Map *m)
{
	if(m != NULL)
	{
		FreeMapList(m->next);
		free(m);
	}
	else
	{
		return 0;	
	}
	
	return 0;
}

inline void
SetInUse(struct Map *m)
{
	set_inuse(m);
}

inline void
SetFree(struct Map *m)
{
	set_free(m);
	set_mappid(m, 0);
}

inline void
SetMapPid(struct Map *m, pid_t pid)
{
	set_mappid(m, pid);
}

int
FreeMaps(struct Map *m)
{
	struct Map *temp;
	
	for(temp = m; temp != NULL; temp = temp->next)
	{
		/* TODO: Change to temp->cursize */
		if((temp->address != 0) && (munmap(temp->address, temp->size) == -1))
		{
			perror("[!] FreeMaps()::munmap");
			return -1;	
		}
		
		if(!temp->name) continue;

		if(unlink(temp->name) == -1)
		{
			if(errno == ENOENT)
				continue;
		
			perror("[!] FreeMaps()::unlink");
			return -1;
		}
	}
	
	return 0;
}

/* Do a binary copy of the two files */

int
CopyFile(char *source, char *destination)
{
	char buffer[1024];
	FILE *s, *d;
	size_t size;
	
	s = fopen(source, "rb");
	d = fopen(destination, "wb");
	
	if(!s || !d)
	{
		perror("[!]	CopyFile()::fopen");
		return -1;
	}
	
	while(!feof(s))
	{
			size = fread((void *) buffer, sizeof(char), sizeof(buffer), s);
			
			if(size < sizeof(buffer))
			{
				if(ferror(s))
				{
					perror("[!]	CopyFile()::fread");
					fclose(s);
					fclose(d);
					
					return -1;
				}
			}
			
			if((fwrite((void *) buffer, sizeof(char), size, d)) < size)
			{
				perror("[!]	CopyFile()::fwrite");
				fclose(s);
				fclose(d);
					
				return -1;
			}
	}

	fclose(s);
	fclose(d);

	return 0;
}

int
PrintMapNames(struct Map *m)
{
	if(!m)
	{
		return 0;
	}
	else
	{
		PrintMapNames(m->next);
		
		printf("	Mapname %s\n", m->name);
		printf("	In use? = %d - %s\n", m->inuse, (m->inuse)? "YES" : "NO");
		printf("	Pid %d\n\n", m->pid);
	}
	
	return 0;
}

/* Return a map name, the returned memory must be freed */
char *
GetMapName(struct Map *m, char *filename)
{
	int ret;
	
	char *outfilename;
	char *tmp;
	
	if(!(outfilename = calloc(1024, sizeof(char))))
	{
		perror("[!] GetMapName()::calloc");
		return NULL;	
	}
	
	ret = strlen(filename);
	tmp = filename + ret;
		
	while((ret-- != 0) && (*(--tmp) != '/'));
	
	if((*tmp != '/') || (*(tmp+1) == '\0'))
	{
		fprintf(stderr, "[!] Error, invalid filename %s\n", filename);
		return NULL;	
	}

	tmp++;
	
	ret = snprintf(outfilename, 1024, "map%.4d-%s", get_id(m), tmp);
	
	if(ret >= 1024)
	{
		fprintf(stderr, "[!] CreateMaps()::snprintf() Filename too long\n");
		return NULL;	
	}
	
	return outfilename;
}

struct Map*
GetMapByPid(struct Map *m, pid_t pid)
{
	struct Map *temp;
	
	for(temp = m; temp != NULL; temp = temp->next)
	{
		if(temp->pid == pid)
		{
			return temp;
		}
	}
	
	return NULL;
}

/* Create 'number' file maps with a base name of 'filename' */

int
CreateMaps(struct Session *s, unsigned int number)
{
	int i;
	struct Map *temp;
	char       *filename = s->input;

	temp        = NULL;
	s->maps     = NULL;

	for(i = 0; i < number; i++)
	{
		if(!(temp = (struct Map *) calloc(1, sizeof(struct Map))))
		{
			perror("[!]	CreateMaps()::malloc");
			goto err;
		}
		
		temp->next = s->maps;
		s->maps    = temp;
		
		set_id(temp, i);
		
		/* Build a map name */
		if((temp->name = GetMapName(temp, filename)) == NULL)
		{
			fprintf(stderr, "[!] Cannot get the map name\n");
			goto err;
		}
		
		/* Duplicate the file */
		if(CopyFile(filename, temp->name) != 0)
		{
			fprintf(stderr, "[!] Cannot copy from map\n");
			free(temp->name);
			goto err;
		}
		
		/* Do the real mmap */
		if((temp->size = MapFile(temp->name, &(temp->address))) <= 0)
		{
			fprintf(stderr, "[!] Error mapping file\n");
			free(temp->name);
			goto err;
		}
	}
	
	return 0;
	
	err:
	
	/* FIXME: just wrong, lazzy ... :| */
	if(temp != NULL)
	{
		s->maps = temp->next;
	}
	
	/* Free the memory mapped files */
	FreeMaps(s->maps);
	
	/* Free the linked list of mappings */
	FreeMapList(s->maps);
	
	free(temp);
	
	return -1;
}

/*
	fuzzno-byteno-filename
	TODO: i should check the snprintf ret value but ... come on :P
*/
char *
GetFilename(char *filename, struct Map *map)
{
	char *tmp;
	char *aux;
	int   ret;

	/* %d-%d-%s*/
	size_t len = strlen(filename) + 20 + 2 + 1;

	char *outfilename = (char *) malloc(len);
	if(!outfilename)
	{
		perror("[!]	GetFilename()::malloc");
		return NULL;
	}
		
	aux = strdup(filename);

	ret = strlen(aux);
	tmp = aux;
	
	while((*(tmp+ret) != '/') && (ret > 0))
	{
		ret--;
	}
	
	if(tmp[ret] == '/' && tmp[ret+1] == '\0')
	{
		fprintf(stderr, "[!]	 Error invalid filename %s i need a filename after the directory\n", aux);
		free(outfilename);
		free(aux);
		return NULL;
	}
	
	if(tmp[ret] == '/' && ret > 0)
	{
		tmp[ret] = 0x00;
		snprintf(outfilename, len, "%s/%d-%d-%s",
			aux, map->fuzzn, map->byten, tmp+ret+1);

		tmp[ret] = '/';
	}
	else if(tmp[ret] == '/' && ret == 0)
	{
		snprintf(outfilename, len, "/%d-%d-%s",
			map->fuzzn, map->byten, tmp+ret+1);
	}
	else
	{
		snprintf(outfilename, len, "%d-%d-%s",
			map->fuzzn, map->byten, aux);
	}
	
	return outfilename;
}

int
DumpMap(struct Session *s, struct Map *map, char *outfilename)
{
	if(CopyFile(map->name, outfilename) == -1)
	{
		free(outfilename);
		return -1;	
	}

	return 0;
}

struct Map *
GetFreeMap(struct Map *m)
{
	struct Map *temp;
	
	for(temp = m; temp; temp = temp->next)
	{
		if(is_free(temp))
		{
			return temp;	
		}
	}
	
	return NULL;
}

int
SyncFileMap(struct Map *m)
{
	if(msync(m->address, m->size, MS_SYNC) == -1)
	{
		perror("[!]	SyncFileMap()::msync");
		return -1;
	}
	
	return 0;
}

int
RefreshMaps(struct Map *maps, struct Map *backup)
{
	struct Map *temp;
	void 	   *newaddr;
	
	for(temp = maps; temp != NULL; temp = temp->next)
	{
		assert(is_free(temp) != 0);

		/* this will be true if MODE_ASCII was used */
		if(temp->size != backup->size)
		{
			#ifdef _GNU_SOURCE
			newaddr = mremap(temp->address, temp->size, backup->size,
				MREMAP_MAYMOVE);
			
			if(newaddr == MAP_FAILED)
			{
				perror("[!] InsertFuzzingString()::mremap");
				return -1;
			}
			#else
			if(munmap(temp->address, temp->size) == -1)
			{
				perror("[!] InsertFuzzingString()::munmap");
				return -1;
			}

			if(MapFile(temp->name, &(newaddr)) == -1)
			{
				return -1;
			}
			#endif

			temp->address = newaddr;
			temp->size    = backup->size;
		}
		
		memcpy(temp->address, backup->address, backup->size);
	}
	
	return 0;
}

struct Map *
CreateBackupMap(char *filename)
{
	struct Map *tmp = calloc(sizeof(struct Map), 1);
	
	if(!tmp)
	{
		perror("[!] CreateBackupMap()::calloc");
		return NULL;
	}
	
	if((tmp->size = MapFile(filename, &(tmp->address))) == -1)
	{
		perror("[!] CreateBackupMap()::mmap");
		free(tmp);
		return NULL;	
	}

	return tmp;
}

int
InsertFuzzingString(struct Session *s, struct Map *m, struct Map *backup)
{
	void *newaddr;
	void *dst;
	void *src;
	size_t len;
	char *mapname;
	int   fd;
	
	if(s->mode == MODE_ASCII)
	{
		/* 
		 * if the current size is not enough to hold the
		 * data we should increase it, also we need to displace
		 * the data at data field's offset to offset + fuzzing string size
		 * so we can insert the data mantaining the file format
		 */
		
		if(m->size != s->filesize + s->curfuzz->size)
		{
			mapname = m->name;
			
			/* open the mmaped file */
			if((fd = open(mapname, O_WRONLY)) == -1)
			{
				perror("[!]	InsertFuzzingString()::open");
				return -1;
			}
			
			/* make it bigger */
			if(ftruncate(fd, s->filesize + s->curfuzz->size) == -1)
			{
				close(fd);
				perror("[!]	InsertFUzzingString()::ftruncate");
				return -1;
			}
			
			/* FIXME: try to make things portable */
			#ifdef _GNU_SOURCE
			/* remap the file */
			newaddr = mremap(m->address, m->size, s->filesize + s->curfuzz->size,
				MREMAP_MAYMOVE);
			
			if(newaddr == MAP_FAILED)
			{
				close(fd);
				perror("[!]	 InsertFuzzingString()::mremap");
				return -1;
			}
			#else
			/* unmap the file */
			if(munmap(m->address, m->size) == -1)
			{
				close(fd);
				perror("[!]	 InsertFuzzingString()::munmap");
				return -1;
			}
			
			m->address = NULL;
			m->size    = 0;
			
			/* map it again but with the new size */
			newaddr = mmap(0, s->filesize + s->curfuzz->size,
				PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

			if(newaddr == MAP_FAILED)
			{
				close(fd);
				perror("[!]	 InsertFuzzingString()::mmap");
				return -1;
			}
			#endif

			close(fd);

			m->address = newaddr;
			m->size    = s->filesize + s->curfuzz->size;
			
			/*
			 *  | keep | memory |
			 *  | keep | s->curfuzz->size bytes | memory |
			 */
			src = ((char *) backup->address) + s->curfield->offset;
			dst = ((char *) m->address) + s->curfield->offset + s->curfuzz->size;

			len = backup->size - s->curfield->offset;
		
			memcpy(dst, src, len);
		}
		
		/*  then insert the fuzzing string */
		memcpy((void *) (((char *) m->address) + s->curfield->offset),
			s->curfuzz->bytes, s->curfuzz->size);
	}
	else
	{
		/* if the current position (offset) plus the size of the
		 * current fuzzing string exeeds the map size, then skip this fs
		 */
		if((s->byte + s->curfuzz->size > m->size) ||
			(s->curfield && (s->curfuzz->size > s->curfield->size)))
		{
			s->skipped++;
			return -2;
		}
	
		memcpy((void *) (((char *) m->address) + s->byte),
			s->curfuzz->bytes, s->curfuzz->size);
	}
	
	return 0;
}
