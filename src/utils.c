#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "gwar.h"
#include "utils.h"

static int
check_error(size_t aux, size_t len)
{
	if(aux == -1 || aux >= len)
	{
		perror("save_context::snprintf()");
		return -1;
	}
	
	return 0;
}

/* 
 * Check this fuction for buffer overflows and the like
 * also check for errors
 */

int
SaveContext(struct Session *s)
{
	FILE *restore;
	size_t len = 1024, aux;
	char *p;
	char *final = (char *) calloc(len, sizeof(char));
	
	if(!final)
	{
		perror("SaveContext::malloc()");
		return -1;	
	}

	s->range.low = s->byte;

	aux = strlen(s->progname);
	
	if(len > aux)
	{
		snprintf(final, len, "%s", s->progname);
		len -= aux;
	}
	
	if(s->input)
	{
		p    = final + strlen(final);
		aux  = snprintf(p, len, " -i %s", s->input);
		
		if(check_error(aux, len) == -1)
		{
			goto err;
		}
		
		len -= aux;
	}

	if(s->output)
	{
		p    = final + strlen(final);
		aux  = snprintf(p, len, " -o %s", s->output);
		
		if(check_error(aux, len) == -1)
		{
			goto err;
		}
		
		len -= aux;
	}

	if(s->extension)
	{
		p    = final + strlen(final);
		aux  = snprintf(p, len, " -e %s", s->extension);
		
		if(check_error(aux, len) == -1)
		{
			goto err;
		}
		
		len -= aux;
	}

	p    = final + strlen(final);
	
	switch(s->mode)
	{
		case MODE_ASCII:
		{
			aux  = snprintf(p, len, " -A");
			break;
		}
		case MODE_BRUTE:
		{
			aux  = snprintf(p, len, " -r %u-%u", s->range.low, s->range.high);
			break;
		}
		case MODE_SMART:
		{
			aux  = snprintf(p, len, " -G %s", s->headers);
			break;
		}
	}
	
	if(check_error(aux, len) == -1)
	{
		goto err;
	}
		
	len -= aux;
	
	if(s->gen && (len > (aux = 3)))
	{
		p = final+strlen(final);
		strcat(p, " -g");
		len -= aux;
	}
	
	if(s->timeout)
	{
		p    = final + strlen(final);
		aux  = snprintf(p, len, " -t %u", s->timeout);
		
		if(check_error(aux, len) == -1)
		{
			goto err;
		}
		
		len -= aux;
	}
	
	if(s->maxproc)
	{
		p    = final + strlen(final);
		aux  = snprintf(p, len, " -m %u", s->maxproc);
		
		if(check_error(aux, len) == -1)
		{
			goto err;
		}
		
		len -= aux;
	}
	
	if(s->skipfuzz)
	{
		p    = final + strlen(final);
		aux  = snprintf(p, len, " -S %u", s->skipfuzz);
		
		if(check_error(aux, len) == -1)
		{
			goto err;
		}
		
		len -= aux;
	}
	
	if(s->dontkill)
	{
		p    = final + strlen(final);
		aux  = snprintf(p, len, " -d");
		
		if(check_error(aux, len) == -1)
		{
			goto err;
		}
		
		len -= aux;
	}
	
	if(s->closefd)
	{
		p    = final + strlen(final);
		aux  = snprintf(p, len, " -C");
		
		if(check_error(aux, len) == -1)
		{
			goto err;
		}
		
		len -= aux;
	}
	
	if(s->command)
	{
		p    = final + strlen(final);
		aux  = snprintf(p, len, " %s", s->command);
		
		if(check_error(aux, len) == -1)
		{
			goto err;
		}
		
		len -= aux;
	}
	
	restore = fopen("restore.sh", "w");
	if(restore)
	{
		fprintf(restore, "%s\n", final);
		fclose(restore);
	}
	else
	{
		perror("save_context::fopen()");
		goto err;
	}
	
	return 0;
	
	err:
	free(final);
	return -1;
}

/*
 * Searches for a token (%FILENAME%) inside an argv[n]
 * array and returns the index where the string was found
 * or -1 in case token is not found.
 */
 
static int
search(char **argv)
{
	int index = 0;
	
	while(argv[index])
	{
		if(strncmp(argv[index], "%FILENAME%", strlen(argv[index])) == 0)
		{
			return index;
		}
		else
		{
			index++;
			if(!argv[index])
			{
				return -1;
			}
		}
	}
	
	return -1;
}

int
PrepareArgv(struct Session *s)
{
	char *tmp;
	char **argv;
	int i = 0;
	int count = 0;	/* space counter */
	
	if(s->gen)
	{
		return 0;		
	}
	
	if(!(s->command))
	{
		fprintf(stderr, "[!] No string to parse!\n");
		return -1;
	}
	
	/* remove spaces at the begining */
	while(*(s->command) == ' ' && *(s->command))
	{
		(s->command)++;
	}
	
	if(*(s->command) == '\0')
	{
		printf("[!] There are no arguments\n");
		return -1;
	}
	
	/* strip off spaces at the end */
	tmp = s->command + strlen(s->command);
	while(*(--tmp) == ' ' && tmp >= (s->command)) *tmp = '\0';
	

	/* count how many arguments we have */
	for(tmp = (s->command); *tmp != '\0'; tmp++)
	{
		if((*tmp == ' ' && *(tmp+1) != ' '))
		{
			count++;
		}
	}
	
	count++;
	
	/* 
	 * prepare argv
	 * +1 because of the null termination needed by execve
	 */ 
	argv = (char **) calloc(count + 1, sizeof(char *));
	if(!argv)
	{
		perror("[!] init_argv::malloc()");
		return -1;
	}
	
	for(tmp = s->command; *tmp != '\0'; tmp++)
	{
		if(*tmp == ' ' && *(tmp+1) != ' ')
		{
			*tmp = '\0';
			argv[i++] = strdup(s->command);
			s->command = tmp + 1;
		}
	}
	
	argv[i] = strdup(s->command);
	
	/*
	 * search for %FILENAME% string in argv, this will return the index
	 * to the location of the string inside argv[]
	 * we well use this index to replace %FILENAME% by the correct output file
	 */
	 
	if((s->index = search(argv)) == -1)
	{
		fprintf(stderr, "[!] Error, %%FILENAME%% is missing in arguments\n");
		return -1;
	}
		
	s->argv = argv;
	return 0;
}
