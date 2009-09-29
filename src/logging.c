#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "gwar.h"

int
CloseLogFile(struct Session *s)
{
	if(!s->logfile) return 0;

	if(fclose(s->logfile) == EOF)
	{
		perror("[!] CloseLogFile::fclose()");
		return -1;		
	}
	
	return 0;	
}

int
OpenLogFile(struct Session *s)
{
	char *tmp = s->command;
	char *name = tmp;
	char *fullname;
	size_t len;
	
	/*
	 * If we are just generating output files
	 * we dont really need logging
	 */
	 
	if(s->gen)
	{
		s->logfile = stdout;	
		return 0;
	}
	
	if(!s->logfilename)
	{
		/*
		 * There is no logfilename, so we take the executable name
		 * and make a execname.log logfile
		 */
		while(*tmp)
		{
			if(*tmp == '/')
			{
				name = tmp+1;
			}
	
			tmp++;
		}

		if(!*name)
		{
			s->logfilename = 0x00;
			return -1;
		}
		
		if((tmp = strdup(name)))
		{
			name = tmp;
			while(*tmp)
			{
				if(*tmp == ' ')
				{
					*tmp = 0x00;
					break;	
				}
				
				tmp++;
			}
		}
		
		len = strlen(name) + strlen(".log") + 2;

		if(!(fullname = malloc(len)))
		{
			return -1;
		}
		
		snprintf(fullname, len, "%s.log", name);
		
		fprintf(stdout, "[%%] Logging to %s\n", fullname);
		s->logfile = fopen(fullname, "a");
		
		free(fullname);
	}
	else if(strcmp(s->logfilename, "stdout") == 0)
	{
		s->logfile = stdout;
	}
	else
	{
		s->logfile = fopen(s->logfilename, "a");
	}

	if(!s->logfile)
	{
		perror("[!] OpenLogFile::fopen()");
		return -1;
	}
	
	return 0;
}

int
PrintLogHeader(struct Session *s)
{
	fprintf(s->logfile, "# Command to be executed:  %s\n", (s->gen) ? "None" : s->command);
	fprintf(s->logfile, "# Input file:              %s\n", s->input);
	fprintf(s->logfile, "# Output file:             %s\n", s->output);
	
	if(s->headers)
	{
		fprintf(s->logfile, "# Fuzzing headers:         %s\n", s->headers);
	}
	else
	{
		fprintf(s->logfile, "# Fuzzing range:           %d to %d\n", s->range.low, s->range.high);
	}

	fprintf(s->logfile, "# Fuzzing session started at: INSERT TIME HERE\n");
	fprintf(s->logfile, "_________________________________________________________________________________________\n");

	return 0;
}
