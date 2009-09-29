#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "gwar.h"
#include "parser.h"

static int
search_delimiter(struct Session *s, char *string, long offset)
{
	int   i, j;
	char *delimiters[] = {"\t", " ", ":", ".", "=", "/", "\\", ",", ";", "<", "{", "[", "(", "<", "/", '\0'};
	int   counter;
	
	i = j = counter = 0;

	while(string[i] != '\0')
	{
		j = 0;
		
		#ifdef DEBUG
		printf("%c", string[i]);
		#endif

		while(delimiters[j] != '\0')
		{
			if(string[i] == *(delimiters[j]))
			{
				Add_DataField(&(DATAFIELD_LIST(s)), offset + i+1, 0);
				counter++;
				
				/* puts("Katrina de chanes"); */
				break;
			}

			j++;
		}

		i++;
	}

	return counter;
}

int
Add_DataField(struct DataField **d, u_int offset, u_int size)
{
	struct DataField *tmp;
	
	if(*d)
	{
		Add_DataField(&((*d)->next), offset, size);
	}
	else
	{
		tmp = (struct DataField *) malloc(sizeof(struct DataField));
		if(!tmp)
		{
			perror("[!] Add_DataField::Malloc()");
			return -1;
		}
	
		tmp->size   = size;
		tmp->offset = offset;
		tmp->next   = NULL;
		*d = tmp;
	}
	
	return 0;
}

/*
 * This try to generate a file structure from an ascii file
 * (could be extended to support binary but...)
 * 
 * For example: 	the input is an html file and 
 * then this prepares all (well almost) the needed datafields
 * inside the html file.
 */

u_int
Extract_ASCII_Structure(struct Session *s)
{
	FILE *file;
	char buffer[512];
	long offset = 0;
	int  counter = 0;

	if(!(file = fopen(s->input, "r")))
	{
		perror("fopen()");
		return 0;
	}

	while(fgets(buffer, sizeof(buffer), file) != NULL)
	{
		counter += search_delimiter(s, buffer, offset);
		
		if((offset = ftell(file)) == -1)
		{
			return 0;	
		}
		
	}

	if(feof(file) == -1)
	{
		perror("fgets()");
		fclose(file);
		return 0;
	}
	
	return counter;	
}

u_int
Extract_DataFields(struct Session *s)
{
	char buffer[512];
	char *ptr;
	int flag, count;
	
	struct DataField *d = NULL;
	
	u_int offset, size, n;
	
	FILE *file = fopen(s->headers, "r");
	if(!file)
	{
		perror("[!] Extract_DataFields::fopen()");
		return 0;
	}

	flag = count = size = 0;

	while(fgets(buffer, sizeof(buffer), file) != NULL)
	{
		if(!flag)
		{
			if((ptr = strstr(buffer, "struct")) != NULL)
			{
				flag = 1;
				/* find name */
				ptr += 6;
				
				while(*ptr && isblank(*ptr))
				{
					ptr++;
				}
				
				if(*ptr)
				{
					sscanf(ptr, "%u", &offset);
				}
			}
			
		}
		else
		{
			if((ptr = strstr(buffer, "int")))
			{
				ptr += 3;
				size = 4;
			}
			else if((ptr = strstr(buffer, "char")))
			{
				ptr += 4;
				size = 1;
			}
			else if((ptr = strstr(buffer, "short")))
			{
				ptr += 5;
				size = 2;
			}
			else if((ptr = strstr(buffer, ";")))
			{
				flag = 0;
			}
			else
			{
				printf("[!] Invalid identifier (Available ID's int,char,short)\n");
				fclose(file);
				return 0;
			}
			
			while(*ptr && isblank(*ptr))
			{
				ptr++;
			}
			
			if(*ptr)
			{
				sscanf(ptr, "%u", &n);
				
				while(n)
				{
					Add_DataField(&d, offset, size);
					count++;
					offset += size;
					n--;
				}
			}
		}
	}
	
	if(feof(file) == -1)
	{
		perror("fgets()");
		fclose(file);
		return 0;
	}
	
	fclose(file);

	s->d = d;

	return count;
}
