#include <unistd.h>
#include <stdio.h>
#include <signal.h>

int
main(void)
{
	raise(SIGSEGV);
	return 0;
}
