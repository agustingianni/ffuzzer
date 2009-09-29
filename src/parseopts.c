#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "gwar.h"
#include "parser.h"
#include "fuzzer.h"
#include "utils.h"
#include "file.h"
#include "signals.h"


#define NEED_ARG 1

struct option longopts[] = {
	{"dump"    ,!NEED_ARG ,  NULL, 'X'}, /* <-- running out of chars :P */
	{"detailed",!NEED_ARG ,  NULL, 'D'},
	{"gen",     !NEED_ARG ,  NULL, 'g'},
	{"ascii",   !NEED_ARG ,  NULL, 'A'},
	{"log",      NEED_ARG ,  NULL, 'L'},
	{"skip",     NEED_ARG ,  NULL, 'S'},
	{"closefd", !NEED_ARG ,  NULL, 'C'},
	{"logfd",	!NEED_ARG ,  NULL, 'l'},
	{"timeout",  NEED_ARG ,  NULL, 't'},
	{"dontkill",!NEED_ARG ,  NULL, 'd'},
	{"sigkill",  NEED_ARG ,  NULL, 's'},
	{"max", 	 NEED_ARG ,  NULL, 'm'},
	{"range", 	 NEED_ARG ,  NULL, 'r'},
	{"restore",  NEED_ARG ,  NULL, 'R'},
	{"string", 	!NEED_ARG ,  NULL, 'S'},
	{"binary", 	!NEED_ARG ,  NULL, 'b'},
	{"output", 	 NEED_ARG ,  NULL, 'o'},
	{"input", 	 NEED_ARG ,  NULL, 'i'},
	{"help", 	!NEED_ARG ,  NULL, 'h'},
	{"ext",		 NEED_ARG ,  NULL, 'e'},
	#ifdef PTRACE
	{"fork",		!NEED_ARG ,  NULL, 'f'}	,
	#endif
	{0,	 0, 	 0, 	0}
};


int
PrintHelp(char *name)
{
	fprintf(stdout, "%s help\n\n", name);
	fprintf(stdout,
	"%s [options] \"command [args] %%FILENAME%%\"\n"
	"\t-X --dump     When a signal is raised dump the file that generated it\n"
	"\t-D --detailed Show detailed information\n"
	"\t-g --gen      Only generate the mutated output files, (This might fill up your disk).\n"
	"\t-A --ascii    Use the ascii engine to test things like XML, etc\n"
	"\t              The input file will grow because we will append the fuzzing strings trying to\n"
	"\t              keep the syntax of the input file correct\n"

	"\t-L --log      Log debugging output to a file\n"
	"\t              stdout logs to standar out\n\n"
	#ifdef PTRACE
	"\t-f --fork     Follow fork, usefull for that interpretates the file inside a child\n"
	#endif
	"\t-G --struct   File with headers definitions\n"
	"\t-e --ext      Add a traling extension to the end of the output filename\n"
	"\t-S --skip     This is used to skip a certain ammount of fuzz variables\n"
	"\t-C --closefd  Try this if you DONT want to close stdin, stdout and stderr\n"
	"\t-l --logfd    This is used to log stdin, stdout and stderr to a file\n"
	"\t-t --timeout  You can specify in how much time the program will time out and stop running\n"
	"\t-d --dontkill If you want to leave the program to run without a timeout\n"
	"\t-s --sigkill  This is the signal that will be raised when we need to kill the procces\n"
	"\t-m --max      The max number of procceses running\n"
	"\t-r --range    Range of bytes to test, examples:\n"
	"\t              0-200 will test from byte 0 to byte 200\n"
	"\t              -200 will test from the beggining of the file to the byte 200\n"
	"\t              0- will test from the byte 0 to the end of the file\n"
/*	"\t-R --restore  Restore an interrupted session\n"*/
	"\t-o --output   This is the output file name, latter we will append the number of the\n"
	"\t              current byte being tested and the number of the fuzzing string\n"
	"\t-i --input    This is the this is the base file\n\n", name);
	
	exit(0);
}

int
ParseArguments(int argc, char **argv, struct Session *session)
{
	int c;
	u_int tmp;

	#ifdef PTRACE
	char *optstring = "XDfgAL:G:e:S:hClt:ds:m:r:R:Sbo:i:";
	#else
	char *optstring = "XDgAL:G:e:S:hClt:ds:m:r:R:Sbo:i:";
	#endif

	if(argc < 2)
	{
		PrintHelp(argv[0]);
	}
	
	while((c = getopt_long(argc, argv, optstring, longopts, NULL)) != EOF)
	{
		switch (c)
		{
			case 'X':
				session->dump   = TRUE;
				break;
			case 'D':
				session->detail = TRUE;
				break;
			#ifdef PTRACE
			case 'f':
				session->followfork = TRUE;
				break;
			#endif
			case 'g':
				session->gen  = TRUE;
				break;
			case 'A':
				session->mode = MODE_ASCII;
				break;
			case 'L':
				session->logfilename = strdup(optarg);
				break;
			case 'G':
				session->headers = strdup(optarg);
				session->mode    = MODE_SMART;
				break;
			case 'e':
				session->extension = strdup(optarg);
				break;
			case 'S':
				session->skipfuzz = (u_int) atoi(optarg);
				break;
			case 'h':
				PrintHelp(argv[0]);
				break;
			case 'C':
				session->closefd = FALSE;
				break;
			case 'l':
				session->logfd = TRUE;
				break;
			case 't':
				session->timeout = (u_int) atoi(optarg);
				break;
			case 'd':
				session->dontkill = TRUE;
				break;
			case 's':
				if((session->killsignum = Str2Sig(optarg)) == -1)
				{
					fprintf(stderr, "Error, invalid signal: %d\n",
					session->killsignum);
					
					return -1;
				}
				break;
			case 'm':
				session->maxproc = (u_int) atoi(optarg);
				break;
			case 'r':
				session->mode    = MODE_BRUTE;	
			
				if(session->input == NULL)
				{
					fprintf(stderr, "You need to specify the input file before the byte range\n");
					return -1;
				}
				
				if((tmp = (u_int) GetFileSize(session->input)) == 0)
				{
					return -1;
				}
				
				session->filesize = tmp;
				
				if(sscanf(optarg,"%u-%u", &(session->range.low), &(session->range.high)) != 2)
				{
					session->range.low  = 0;
					session->range.high = tmp - 1;

					if(sscanf(optarg,"-%u", &(session->range.high)) != 1)
					{
						session->range.low  = 0;
						session->range.high = tmp - 1;

						if(sscanf(optarg,"%u-", &(session->range.low)) != 1)
						{
							fprintf(stderr, "Invalid byte range\n");
							return -1;
						}
					}
				}
				
				if(session->range.low > session->range.high)
				{
					fprintf(stderr, "Invalid range, lower limit is greater higher limit\n");
					return -1;	
				}
				
				if(session->range.low > tmp || session->range.high > tmp)
				{
					fprintf(stderr, "Invalid range, lower limit (%u) or superior limit (%u) "
									"is greater than file size (%u)\n",
									session->range.low,
									session->range.high,
									tmp);
					return -1;
				}
				break;
			case 'R':
				break;
			case 'o':
				if(!(session->output = strdup(optarg)))
				{
					perror("Changos...\n");	
					return -1;
				}
				break;
			case 'i':
				if(!(session->input = strdup(optarg)))
				{
					perror("Changos...\n");	
					return -1;
				}
				break;
			case '?':
			default:
				printf("Not a valid argument...\n");
				return -1;
				break;
		}
	}
	
	if(!(session->input))
	{
		fprintf(stderr, "Error, specify an input file (--input)\n");
		return -1;
	}
	else if(!session->filesize)
	{
		if((session->filesize = (u_int) GetFileSize(session->input)) == 0)
		{
			return -1;
		}
	}
	
	if(!(session->output))
	{
		fprintf(stderr, "Error, specify an output file (--output)\n");
		return -1;
	}
	
	if((session->range.low == 0) && (session->range.high == 0) &&
	(session->headers == NULL) && (session->mode != MODE_ASCII))
	{
		fprintf(stderr, "Error, you need to specify either a valid range\n"
				"or a file with header definitions\n");
		return -1;
	}
	
	if(session->headers && session->range.high)
	{
		fprintf(stderr, "Error, you need to specify either a valid range\n"
				"or a file with header definitions not both\n");
		return -1;
	}
	
	if(session->gen)
	{
			fprintf(stdout, "[i] Generation mode ON\n");
			session->command = NULL;
	}
	else if(!(argv[optind]))
	{
		fprintf(stderr, "Missing argument, i need a target program to fuzz.\n");
		return -1;
	}
	else
	{
		session->command = strdup(argv[optind]);
		if(!session->command)
		{
			perror("parseopt():");
			return -1;
		}
	}

	return 0;
}
