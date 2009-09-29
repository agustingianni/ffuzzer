#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <locale.h>
#include <langinfo.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h> 

static void lookup(char *path)
{
    DIR *dirp;
    struct dirent *dp;
	struct stat     statbuf;
	unsigned int cleaned = 0;

	if(chdir(path) == -1)
	{
		fprintf(stderr, "Cannot change to dir '%s'\n", path);
		return;
	}

    if ((dirp = opendir(path)) == NULL)
	{
		fprintf(stderr, "Cannot open '%s'\n", path);
        return;
    }

    while ((dp = readdir(dirp)) != NULL)
	{
        errno = 0;
		if (stat(dp->d_name, &statbuf) == -1)
		{
        	continue;
		}

	    if(statbuf.st_size == 0)
		{
			if(unlink(dp->d_name) == -1)
			{
				perror("Cannot unlink:");
				continue;
			}

			cleaned++;
		}

    }

	fprintf(stdout, "Succesfully cleaned %d files\n", cleaned);

    closedir(dirp);
    return;
}

int
main(int argc, char **argv)
{
	if(argv[1])
	{
		lookup(argv[1]);
	}
	else
	{
		fprintf(stderr, "Tinny utility to clean up 0 size files\n"
						"Error: I need a directory as an argument to clean\n"
						"Use:	%s <to_cleanup>\n", argv[0]);
		return -1;
	}

	return 0;
}
