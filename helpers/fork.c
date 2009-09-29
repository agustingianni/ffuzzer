#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>

int
main(int argc, char **argv)
{
	pid_t pid;

	pid = fork();

	if(pid == 0)
	{
		int a;
		sleep(atoi(argv[1]));
		a = 2/(1-1);

		_exit(0);
	}
	else if(pid == -1)
	{
		puts("Error fork()");
		_exit(-1);
	}

	waitpid(-1, NULL, 0);
	
	return 0;
}
