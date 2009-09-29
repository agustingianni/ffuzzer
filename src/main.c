/*
 * Author - Agustin Gianni (agustingianni@gmail.com)
 *
 * The code needs a re-desing, this has grown much more than I
 * expected, so it is a little mess, and I already got bored
 * so do not expect a full rewrite.
 *
 * Web:  http://agustingianni.googlepages.com/
 * Blog: http://gruba.blogspot.com/
 * 
 * I must give thanks to Gaston Traberg and Bastian Reich for their help
 * and ideas, thank you guys.
 * 
 * Any questions or much better .diff's with improvements can
 * be sent to the e-mail address above.
 * 
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <mcheck.h>

#include "gwar.h"
#include "parser.h"
#include "fuzzer.h"
#include "utils.h"
#include "file.h"
#include "signals.h"
#include "parseopts.h"
#include "logging.h"
#include "mappings.h"

static void
InitSession(struct Session *s, char **envp, char **argv)
{
	memset((void *) s, 0x00, sizeof(struct Session));

	s->detail      = FALSE;
	s->gen         = 0;
	s->timeout     = 3;
	s->maxproc     = 3;
	s->dontkill    = FALSE;
	s->mode        = MODE_SMART;
	s->closefd     = TRUE;
	s->logfd       = FALSE;
	s->killsignum  = SIGKILL;
	s->envp        = envp;
	s->headercount = 0;
	s->progname    = argv[0];
	return;
}

int
main(int argc, char **argv, char **envp)
{
	struct Session session;
	time_t	t1, t2;

	int tmp = 0;

	if(RegisterHandlers() == -1)
	{
		fprintf(stderr, "[!] Cannot register signal handlers, aborting\n");
		goto cleanup;
	}
	
	InitSession(&session, envp, argv);

	if(ParseArguments(argc, argv, &session) == -1)
	{
		PrintHelp(argv[0]);
		goto cleanup;
	}

	if(OpenLogFile(&session) == -1)
	{
		fprintf(stderr, "[!] Cannot open %s for logging, aborting\n",
			session.logfilename);

		goto cleanup;
	}

	if(PrepareArgv(&session) == -1)
	{
		fprintf(stderr, "[!] Cannot parse arguments\n");
		goto cleanup;
	}
	
	if(InitFuzzingStrings(&session) == -1)
	{
		fprintf(stderr, "[!] Error initializing fuzzing variables\n");
		goto cleanup;
	}

	switch(session.mode)
	{
		/* Smart mode read the file structure from a file */ 
		case MODE_SMART:
		{
			fprintf(stdout, "[%%] Reading headers structure from %s\n",
			session.headers);

			session.headercount = Extract_DataFields(&session);
			break;
		}
		/* ASCII mode read a file and tries to get the right file structure =) */
		case MODE_ASCII:
		{
			fprintf(stdout, "[%%] Reading ASCII structure from %s\n",
				session.input);
			
			session.headercount = Extract_ASCII_Structure(&session);
			break;
		}
	}

	if((session.mode == MODE_ASCII) || (session.mode == MODE_SMART))
	{
		if(!session.headercount)
		{
			fprintf(stderr, "[!] Error loading Offsets from input file\n");
			goto cleanup;
		}

		session.range.low   = 0;
		session.range.high  = session.headercount;
		
		fprintf(stdout, "[%%] Loaded %d fields in headers\n",
			session.headercount);
	}

	tmp = CountFuzzingStrings(&session);
	
	fprintf(stdout, "[%%] Loaded %d fuzzing variables\n", tmp);
	fprintf(stdout, "[%%] Fuzzing from %d to %d\n",	session.range.low,
		session.range.high);
	
	if(session.mode == MODE_BRUTE)
	{
		session.byte = session.range.low;
		tmp         *= session.range.high - session.range.low + 1;
	}
	else
	{
		session.curfield = session.d;
		session.byte     = session.curfield->offset;
		tmp             *= session.headercount;
	}

	PrintLogHeader(&session);

	fprintf(stdout, "[%%] Number of files to be generated %d\n", tmp);
	fprintf(stdout, "[%%] Proceding with fuzzing\n");

	time(&t1);
	StartSession(&session);
	time(&t2);

	fprintf(stdout, "[%%] Time elapsed %f\n", difftime(t2, t1));
	fprintf(stdout, "[%%] Number of succesful executions %d\n", session.exec);
	fprintf(stdout, "[%%] Skipped executions due to fuzzing string size %d\n", session.skipped);
	fprintf(stdout, "[%%] Number of \"bugs\" found: %d\n", session.bugs);
	
	/* Cleanup Resources */
	cleanup:
	{
		FreeFuzzingList(session.f);
		FreeMaps(session.maps);
		CloseLogFile(&session);
	}
	
	return 0;
}

