#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h> 
#include <sys/wait.h> 
#include <fcntl.h>
#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <math.h>
#include <assert.h>
#include "gwar.h"
#include "parser.h"
#include "fuzzer.h"
#include "utils.h"
#include "signals.h"
#include "file.h"
#include "PexLike.h"
#include "mappings.h"
#include "process.h"

sig_atomic_t signaled = FALSE;

/*
 * This routine free's Fuzzing strings linked list 
 */
int
FreeFuzzingList(struct fuzzes *f)
{
	if(f != NULL)
	{
		FreeFuzzingList(f->next);
		free(f->bytes);
		free(f);		
	}
	
	return 0;
}

/*
 * Add fuzzing string sorted by size (important)
 */
 
static int
AddFuzzingString(void *bytes, u_int size, struct fuzzes **f)
{
	struct fuzzes *tmp, *w,*prev;
		
	tmp = (struct fuzzes *) calloc(1, sizeof(struct fuzzes));
	if(!tmp)
	{
		perror("[!] add_fuzzer::calloc()");
		exit(-1);
	}
	
	tmp->size = size;
	tmp->bytes = (void *) calloc(1, size);
	if(!(tmp->bytes))
	{
		free(tmp);
		perror("[!] add_fuzzer()::calloc()");
		exit(-1);
	}
	
	memcpy(tmp->bytes, bytes, size);
	
	prev = NULL;
	w	 = *f;
	
	while(w != NULL && tmp->size >= w->size)
	{
		prev = w;
		w    = NEXT_ITEM(w);
	}
	
	NEXT_ITEM(tmp) = w;
	if(prev)
	{
		NEXT_ITEM(prev) = tmp;
	}
	else
	{
		*f = tmp;
	}
	
	return 0;
}

static void AddShort16(u_int16_t integer,int msb, struct fuzzes **f)
{
	if (msb)
	{
		integer = htons(integer);
	}

	AddFuzzingString((void *)&integer,2,f);
}

static void AddInt32(u_int32_t integer,int msb, struct fuzzes **f)
{
	if (msb)
	{
		integer = htonl(integer);
	}

	AddFuzzingString((void *)&integer,4,f);
}

/*
 * Initialize fuzzing variables
 * Try to be clever adding fuzzing strings
 * the power of the fuzzer is on its strings (so far)
 * Some of these were taken from other public fuzzers
 * like fileSPIKE, SPIKE, etc.
 */

#ifdef FUZZ_ALL 
  #define FUZZ_ASCII
  #define FUZZ_BINARY
#endif

int
InitFuzzingStrings(struct Session *s)
{
	char *p;
	int   i;
	
	struct fuzzes **f = &(s->f);

	#ifdef TEST
	{
	  AddFuzzingString("----", 4, f);
	  AddFuzzingString("++++", 4, f);
	  return 0;
	}
	#endif

	#ifdef FUZZ_ASCII
	int  u;
	long power;
	char buffer[32768+1];

	AddFuzzingString("%n%n%n%n%n%n", 13, f);
	
	/* Many people use powers of 2 as buffer size so this might help */
	for(u = 0; u <= 15; u++)
	{
		memset((void *) buffer, 0xff, u+1);
		buffer[u+1] = 0x00;
		AddFuzzingString(buffer, strlen(buffer), f);
		
		power = pow(2, u);
		
		memset((void *) buffer, 0x41, (int) power);
		buffer[power] = 0x00;
		AddFuzzingString(buffer, strlen(buffer), f);
		
		memset((void *) buffer, 0xff, (int) power);
		AddFuzzingString(buffer, strlen(buffer), f);
	}
	
	/* Add some patterns, using a pattern like Pex in metasploit
	 * so we can look for them later debugging with pyPatternSearch.py
	 */
	for(i = 1024; i <= 8192; i *= 2)
	{
		p = PatternCreate(i);
		AddFuzzingString(p, i, f);
		free(p);
	}

	/* some "integers" */
	AddFuzzingString("65535", 6,f);
	AddFuzzingString("65534", 6,f);
	AddFuzzingString("2147483647", 11,f);
	AddFuzzingString("2147483648", 11,f);
	AddFuzzingString("-1", 3,f);
	AddFuzzingString("4294967295", 11,f);
	AddFuzzingString("4294967294", 11,f);
	AddFuzzingString("0", 2,f);
	AddFuzzingString("1", 2,f);
	AddFuzzingString("357913942", 10,f);
	AddFuzzingString("-2147483648", 12,f);
	AddFuzzingString("536870912", 10,f);
	#endif

	#ifdef FUZZ_BINARY
	for ( i=2;i<16;i+=2 )
	{
		AddInt32(0xffffffff/i+1,0,f);
		AddInt32(0xffffffff/i+1,1,f);
		AddShort16((0xffff/i)+1,0,f);
		AddShort16((0xffff/i)+1,1,f);
		AddInt32((0xffffffff/i),0,f);
		AddInt32((0xffffffff/i),1,f);
		AddShort16((0xffff/i),0,f);
		AddShort16((0xffff/i),1,f);
	}
	
	for ( i=-8;i<8;i++ )
	{
		AddShort16((short)i,0,f);
		AddShort16((short)i,1,f);
		AddInt32(i,0,f);
		AddInt32(i,1,f);
	}
	
	AddFuzzingString("\xca\xfe\xba\xbe",4,f);
	AddFuzzingString("\xbe\xba\xfe\xca",4,f);
	AddFuzzingString("\x00\x00\x00\x00",4,f);
	AddFuzzingString("\x00\x00\x00\x00\x00\x00\x00\x00",8,f);
	AddFuzzingString("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",16,f);

	/* Adding some interesting strings to test things like gcc, lynx etc */
	if(s->mode == MODE_ASCII)
	{
		for(i = 0x00; i <= 0x0f; i++)
		{
			AddFuzzingString((void *) ((char *) &i), 1, f);
		}

		for(i = 0x20; i <= 0x2e; i++)
		{
			AddFuzzingString((void *) ((char *) &i), 1, f);
		}
	}
	#endif
	
	return 0;
}

/* Return the number of fuzzing strings loaded */
int
CountFuzzingStrings(struct Session *s)
{
	struct fuzzes *f = s->f;
	int count = 0;
	
	while(f != NULL)
	{
		count++;
		f = NEXT_ITEM(f);
	}
	
	return count;
}

static int
PrintProgress(struct Session *s)
{
	if(s->mode == MODE_BRUTE)
	{
		printf("[%%] Byte [%5ld] FuzzString [%5d] Process [%2d] Bugs? [%d]\r",
			s->byte, s->fuzzcount, s->currentprocs, s->bugs);
	}
	else
	{
		printf("[%%] Remaining data fields [%5d] [BUGS %d]\r",
			s->headercount, s->bugs);
	}

	fflush(stdout);
	return 0;
}

static int
NextByte(struct Session *s)
{
	if(s->mode == MODE_BRUTE)
	{
		/* Check if we are done with the fuzzing range*/
		if((s->byte++) >= s->range.high)
		{
			return 0;
		}
	}
	else
	{
			/*
			 *  If this is NULL Then its the firstime
			 *  we call this function
			 */
			 
			if(s->curfield == NULL)
			{
				s->curfield = s->d;
			}
			else
			{
				s->curfield = NEXT_ITEM(s->curfield);
				(s->headercount)--;
			}
			
			/* Now if *d is NULL again this means we are Done checking datafields */
			if(s->curfield == NULL)
			{
				return 0;
			}
			
			/* 
			 * All the datafields have an offset measured in bytes, so
			 * the actual fuzzing byte is set to that offset inside the file
			 */
			s->byte = s->curfield->offset;
	}

	return 1;
}

/* Redirect stdin, stdout and stderr to /dev/null to avoid the program output */
static int
RedirectStreams()
{
	int i = open("/dev/null", O_RDWR, 0640); 
	
	if(i == -1)
	{
		perror("[!]	RedirectStreams()::open");
		return -1;
	}
	
	if (dup2(i, STDIN_FILENO) != STDIN_FILENO)
	{
		fprintf(stderr, "[!] Could not redirect stdin to /dev/null: %s\n",
			strerror(errno));
		return -1;
	}
	
	if (dup2(i, STDOUT_FILENO) != STDOUT_FILENO)
	{
		fprintf(stderr, "[!] Could not redirect stdout to /dev/null: %s\n",
			strerror(errno));
		return -1;
	}
	
	if (dup2(i, STDERR_FILENO) != STDERR_FILENO)
	{
		fprintf(stderr, "[!] Could not redirect stderr to /dev/null: %s\n",
			strerror(errno));
		return -1;
	}
	
	return 0;
}

/* Fork and execute the program */
static pid_t
DoExecve(struct Session *s)
{
	pid_t pid;

	switch((pid = fork()))
	{
		case -1:
		{
			perror("[!] DoExecv::fork()");
			break;
		}
		case 0:
		{
			setpgid(0,0);	/* ;) */

			if(s->closefd)
			{
				if(RedirectStreams() == -1)
				{
					_exit(-1);
				}
			}
					
			if(s->timeout)
			{
				alarm(s->timeout);
			}
			
			if(nice(1) == -1)	/* ;) */
			{
				perror("[!] DoExecv::nice(1)");
			}

			#ifdef PTRACE
			if(ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
			{
				perror("[!] DoExecv::ptrace(PTRACE_TRACEME)");
				_exit(-1);
			}
			
			/* Synchronize */
			raise(SIGUSR1);
			#endif

			if(execve(s->argv[0], s->argv, s->envp) == -1)
			{
				perror("[!] DoExecv::execve()");
				_exit(-1);
			}
			
			break;
		}
		default:
		{
			#ifdef DEBUG
			{
				fprintf(stderr, "[DEBUG] Parent created [%d]\n", pid);	
			}
			#endif
			
			#ifdef PTRACE
			if(AddParentProcess(&(s->process), pid) == -1)
			{
				/* Maybe we need to kill the new child */
				return -1;
			}
			#endif
			
			s->exec++;
			INC_PROC_COUNT(s);
			break;
		}
	}
	
	return pid;
}


static void
SkipFuzzingStrings(struct Session *s)
{
	if(s->skipfuzz)
	{
		fprintf(stdout, "[%%] Skipping (%d) fuzzing variables\n", s->skipfuzz);
	}
			
	s->fuzzcount = s->skipfuzz;
	s->curfuzz   = FUZZING_LIST(s);
		
	while(s->fuzzcount)
	{
		s->curfuzz = NEXT_ITEM(s->curfuzz);
		s->fuzzcount--;
	}
}

static int
NextFuzzingString(struct Session *s)
{
	if(s->curfuzz)
	{
		s->fuzzcount++;
		s->curfuzz = NEXT_ITEM(s->curfuzz);

		if(s->curfuzz == NULL)
		{
			s->fuzzcount = 0;
			s->curfuzz = FUZZING_LIST(s);
			return 0;
		}
	}
	else
	{
		s->fuzzcount = 0;
		s->curfuzz = FUZZING_LIST(s);
		return 0;
	}
	
	/* I love this :P heheh */
	return 1;
}

/* Generate output files without executing any program
   its usefull to test things like ClamAV ;) */
int
GenerateFiles(struct Session *s)
{
	struct Map *freemap;
	struct Map *backup;
	char       *filename;

	if((backup = CreateBackupMap(s->input)) == NULL)
	{
		fprintf(stderr, "[!] Error crating backup map\n");
		return -1;
	}

	do
	{
		do
		{
			if(signaled)
			{
				SaveContext(s);
				goto cleanup;
			}
			
			freemap = GetFreeMap(s->maps);
			
			SetInUse(freemap);
			
			/* The unique id is used to generate the output filename */
			SetUniqueID(freemap, s->fuzzcount, s->byte);
			
			switch(InsertFuzzingString(s, freemap, backup))
			{
				case -2:
				{
					s->fuzzcount = 0;
					s->curfuzz   = NULL;

					SetFree(freemap);
					continue;
					break;
				}
				case -1:
				{
					fprintf(stderr,
						"\n[!] Error inserting Fuzzing String\n");
					goto cleanup;
					break;
				}
			}

			if(SyncFileMap(freemap) != 0)
			{
				fprintf(stderr, "\n[!] Error with file sync\n");
				goto cleanup;
			}

			if(!(filename = GetFilename(s->input, freemap)))
			{
				fprintf(stderr, "\n[!] Error with file sync\n");
				goto cleanup;
			}

			DumpMap(s, freemap, filename);
			SetFree(freemap);

			free(filename);
		}
		while(NextFuzzingString(s));
		
		RefreshMaps(s->maps, backup);

		#ifndef QUIET
		PrintProgress(s);
		#endif
		
		if(getchar() == 'n') { goto cleanup; }
	}
	while(NextByte(s));

	/* Cleanup all pending childs */
	cleanup:
	return 0;
}

int
StartSession(struct Session *s)
{
	struct Map *freemap;
	struct Map *backup;
	int         ret = 0;
	pid_t       pid = 0;

	SkipFuzzingStrings(s);

	if(CreateMaps(s, s->maxproc) == -1)
	{
		fprintf(stderr, "[!] Error creating file maps\n");
		return -1;
	}

	if((backup = CreateBackupMap(s->input)) == NULL)
	{
		fprintf(stderr, "[!] Error crating backup map\n");
		return -1;
	}

	do
	{
		/* For each offset do:*/
		do
		{
			/* For each fuzzing string do: */
			
			if(signaled)
			{
				fprintf(stdout, "\n[!] Received SIGINT, saving restore data to restore.sh\n");
				SaveContext(s);
				goto err;
			}

			while(!(freemap = GetFreeMap(s->maps)))
			{
				assert(WaitForSignal(s) != -1); 
			}

			/* Map is now being used */
			SetInUse(freemap);

			/* The unique id is used to generate the output filename */
			SetUniqueID(freemap, s->fuzzcount, s->byte);
			
			ret = InsertFuzzingString(s, freemap, backup);

			switch(ret)
			{
				case -2:
				{
					s->fuzzcount = 0;
					s->curfuzz   = NULL;
					SetFree(freemap);
					continue;
					break;
				}
				case -1:
				{
					fprintf(stderr,
					"\n[!] Error inserting Fuzzing String\n");
					goto err;
					break;
				}
			}

			/* Synchronize the file (hd) and the filemap */
			if(SyncFileMap(freemap) != 0)
			{
				fprintf(stderr, "\n[!] Error with file sync\n");
				goto err;
			}
			
			s->argv[s->index] = freemap->name;
			
			if((pid = DoExecve(s)) == -1)
			{
				fprintf(stderr, "\n[!] Error executing command\n");
				goto err;
			}
			
			SetMapPid(freemap, pid);
		}
		while(NextFuzzingString(s));
		
		/* while(WaitForSignal) */
		WaitChilds(s);

		RefreshMaps(s->maps, backup);

		#ifndef QUIET
		PrintProgress(s);
		#endif
	}
	while(NextByte(s));

	NEWLINE();
	
	/* Cleanup all pending childs */
	err:
	{
		/* while(WaitForSignal) */
		WaitChilds(s);
	}

	FreeMaps(backup);

	return ret;
}
