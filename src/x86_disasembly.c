 #include <sys/ptrace.h>
 #include <sys/types.h>
 #include <sys/wait.h>
 #include <stdio.h>
 #include <unistd.h>
 #include <errno.h>
 #include <stdlib.h>
 #include <sys/user.h>
 #include <signal.h>
 #define _GNU_SOURCE
 #include <string.h>
 #include <ctype.h>
 #include "gwar.h"
 #include "file.h"
 #include "utils.h"
 #include "signals.h"
 #include "distorm.h"
 
 #define MAX_INSTRUCTIONS 100

 int
 PrintGeneralRegisters(FILE *file, struct user_regs_struct reg)
 {
 	fprintf(file, "\tRegisters dump:\n"
				  "\t---------------\n\n");
 	
 	fprintf(file,
		"\teax = 0x%.8lx\t"	"ebx = 0x%.8lx\t"	"ecx = 0x%.8lx\n"
		"\tedx = 0x%.8lx\t"	"esi = 0x%.8lx\t"	"edi = 0x%.8lx\n"
		"\tebp = 0x%.8lx\t"	"esp = 0x%.8lx\t"	"eip = 0x%.8lx\n\n",
 		reg.eax,	reg.ebx,	reg.ecx,
		reg.edx,	reg.esi,	reg.edi,
		reg.ebp,	reg.esp, 	reg.eip
 	);

	return 0;
 }

 void
 DumpHex(FILE *file, void *buffer, int size, int pad)
 {
	int j;

	for(j=0; j < size;j++)
	{
		fprintf(file, "%.2x ", *(((u_char *)buffer)+j));
	}
	
	for(j = 0; j < pad; j++)
	{
		fprintf(file, "   ");
	}

	printf("\t");

	for(j = 0; j < size; j++)
	{
		if(isprint((u_char) *(((u_char *)buffer)+j)))
		{
			fprintf(file, "%c", ((u_char) *(((u_char *)buffer)+j)));
		}
		else
		{
			fprintf(file, ".");
		}
	}
	
	fprintf(file, " \n");
 }

 int
 GetGeneralRegisters(pid_t pid, struct user_regs_struct *reg)
 {
 	if(ptrace(PTRACE_GETREGS, pid, NULL, reg) == -1)
	{
		perror("[!] GetGeneralRegisters::ptrace(PTRACE_GETREGS)");
		return -1;
	}

 	return 0; 	
 }

 int
 ReadProcessMemory(pid_t pid, void *addr, void *buffer, u_int size)
 {
	long word;
	void *ptr = addr;	
	u_int i = 0;
	
	while(i < size)
	{
		word = ptrace(PTRACE_PEEKTEXT, pid, ptr, NULL);
		if((word == -1) && (errno))
		{
			if(errno == EIO)
			{
				fprintf(stderr, "[!] Invalid address address %p\n", ptr);
				memcpy((void *) (((char *) buffer)+i),
					"\x00\x00\x00\x00", sizeof(long));
				
				i   += sizeof(long);
				ptr = (void *) (((char *) ptr) + sizeof(long));
				continue;
			}

			perror("[!] get_x86_memory::ptrace(PTRACE_PEEKTEXT)");
			return -1;
		}
		else
		{
			memcpy((void *) (((char *)buffer)+i),
				(void *) &word, sizeof(long));

			i   += sizeof(long);
			ptr = (void *) (((char *) ptr) + sizeof(long));
		}
	}

	return i;
 }

 int
 PrintStackFrame(FILE *file, pid_t pid, struct user_regs_struct reg)
 {
	u_int frame_size;
	void  *frame_address;
	char  *buffer;
	int    i;

	int times;

	if(reg.ebp < reg.esp)
	{
		fprintf(file, "[i] EBP is smaller than ESP, maybe the stack pointers were corrupted\n");
		return 0; 	
	}

	fprintf(file, "\tStack frame dump:\n"
				  "\t-----------------\n\n");

	frame_size 		= reg.ebp - reg.esp;
	frame_address 	= (void *) reg.esp;

	if(!(buffer = malloc(frame_size)))
	{
		perror("[!] print_x86_stack_frame::malloc()");
		return -1;
	}

	if(ReadProcessMemory(pid, frame_address, buffer, frame_size) == -1)
	{
		free(buffer);
		return -1;
	}
	
	times = frame_size / 16;

	for(i = 0; i < times; i++)
	{
		fprintf(file, "\t0x%.8lx:\t", (u_long) (((char *) frame_address)+(i*16)));
		DumpHex(file, buffer+(i*16), 16,0);
	}

	fprintf(file, "\t0x%.8lx:\t", (u_long) (((char *) frame_address)+(i*16)));

	DumpHex(file, buffer+(i*16), frame_size - times*16, 16-(frame_size - times*16));

	fprintf(file, "\n");
	free(buffer);
	return 0;
 }

 int PrintDisassembly(FILE *file, pid_t pid, struct user_regs_struct regs)
 {
	_DecodeResult res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];

	u_int  decodedInstructionsCount = 0;
	u_int  i		= 0;
	u_int  z        = 0;
	u_char *buf		= NULL;
	u_char  found	= FALSE;
	size_t  size    = 0;
	
	if(!(buf = (void *) malloc(100)))
	{
		perror("[!] print_x86_context::malloc()");
		return -1;
	}

	if((size = ReadProcessMemory(pid, (void *) ((regs.eip) - 50) , buf, 100)) == -1)
	{
		free(buf);
		return -1;
	}

	fprintf(file, "\tDisassembly dump:\n"
		"\t-----------------\n\n");

	/* Search for the beggining of the assembly block */
	while (i < size)
	{
		res = distorm_decode
		(
			regs.eip - 50 + i,
			(const unsigned char *) buf + i,
			100 - i,
			Decode32Bits,
			decodedInstructions,
			MAX_INSTRUCTIONS,
			&decodedInstructionsCount
		);

		for (z = 0; z < decodedInstructionsCount; z++)
		{
			if(decodedInstructions[z].offset == regs.eip)
			{
				found = TRUE;
				break;
			}
		}

		if ((res == DECRES_SUCCESS) || (decodedInstructionsCount == 0))
		{
			break;
		}

		i++;
	}

	if(!found)
	{
		free(buf);
		fprintf(file, "\tCannot find the starting point of the assembly block\n");
		
		return -1;
	}

	/* Decode the buffer at given offset (virtual address).*/
	for (i = 0; i < decodedInstructionsCount; i++)
	{
		if(decodedInstructions[i].offset == regs.eip)
		{
			fprintf(file, "EIP ->");
		}

		fprintf(file, 
			"\t\t%llx %-12s   %s\n", 
			decodedInstructions[i].offset, 
			decodedInstructions[i].mnemonic.p, 
			decodedInstructions[i].operands.p
		);
	}

	free(buf);
	return 0;
 }
