 #ifdef BSD
  #undef _GNU_SOURCE
 #else
  #define _GNU_SOURCE
 #endif

 #include <signal.h>
 #include <string.h>
 #include <sys/wait.h>
 #include <errno.h>
 #include <stdio.h>
 #include <unistd.h>
 #include <stdlib.h>
 #include <sched.h>
 #include <assert.h>
 #include "gwar.h"
 #include "mappings.h"
 #include "process.h"
 
 #ifdef PTRACE
	#include <sys/ptrace.h>
	#include <sys/reg.h>
	#include <sys/types.h>
	#include <sys/user.h>
	#include <sys/syscall.h>	/* For SYS_write etc */

	#define PTRACE_EVENT_FORK       1
	#define PTRACE_EVENT_VFORK      2
	#define PTRACE_EVENT_CLONE      3
	#define PTRACE_EVENT_EXEC       4
	#define PTRACE_EVENT_VFORK_DONE 5
	#define PTRACE_EVENT_EXIT       6

	#define PTRACE_SETOPTIONS       0x4200
	#define PTRACE_GETEVENTMSG      0x4201
	#define PTRACE_GETSIGINFO       0x4202
	#define PTRACE_SETSIGINFO       0x4203
 
	#define PTRACE_O_TRACESYSGOOD   0x00000001
	#define PTRACE_O_TRACEFORK      0x00000002
	#define PTRACE_O_TRACEVFORK     0x00000004
	#define PTRACE_O_TRACECLONE     0x00000008
	#define PTRACE_O_TRACEEXEC      0x00000010
	#define PTRACE_O_TRACEVFORKDONE 0x00000020
	#define PTRACE_O_TRACEEXIT      0x00000040
 #endif	/* END PTRACE */

 #include "gwar.h"
 #include "file.h"
 #include "signals.h"
 #include "utils.h"
 #include "mappings.h"
 
 #include "process.h"

 extern int LogDetails(struct Session *, pid_t, int);

 /* from man 7 signal */
 struct Signals signals[] =
 {
	{SIGHUP,	"Hangup on terminal or control process death",	"SIGHUP"},
	{SIGINT,	"Interrupt from keyboard",			"SIGINT"},
	{SIGQUIT,	"Quit from keyboard",				"SIGQUIT"},
	{SIGILL,	"Illegal instruction",				"SIGILL"},
	{SIGTRAP,	"Trace/breakpoint trap",			"SIGTRAP"},
	{SIGABRT,	"Abort signal from abort()",			"SIGABRT"},
	{SIGBUS,	"Bus error (bad memory access)",		"SIGBUS"},
	{SIGKILL,	"Kill signal",					"SIGKILL"},
	{SIGUSR1,	"User-defined signal 1",			"SIGUSR1"},
	{SIGUSR2,	"User-defined signal 2",			"SIGUSR2"},
	{SIGPIPE,	"Broken pipe: write to pipe with no readers",	"SIGPIPE"},
	{SIGALRM,	"Timer signal from alarm(2)",			"SIGALRM"},
	{SIGTERM,	"Termination signal",				"SIGTERM"},
	{SIGCONT,	"Continue if stopped",				"SIGCONT"},
	{SIGSTOP,	"Stop process",					"SIGSTOP"},
	{SIGTSTP,	"Stop tiped at tty",				"SIGSTP"},
	{SIGXCPU,	"CPU time limit exceeded (4.2 BSD)",		"SIGXCPU"},
	{SIGVTALRM,	"Virtual alarm clock (4.2 BSD)",		"SIGVTALRM"},
	{SIGPROF,	"Profiling alarm clock",			"SIGPROF"},
	{SIGWINCH,	"Window size change",				"SIGWINCH"},
	{SIGIO,		"I/O now possible",				"SIGIO"},
	{SIGSYS,	"Bad system call",				"SIGSYS"},
	{SIGSEGV,	"Segmentation violation",			"SIGSEGV"},
	{SIGTTIN,	"Background read from tty",			"SIGTTIN"},
	{SIGTTOU,	"Background write to tty",			"SIGTTOU"},
	{SIGURG,	"Urgent condition on socket",			"SIGURG"},
	{SIGXFSZ,	"File size limit exceeded",			"SIGXFSZ"},
	{SIGFPE,	"Floating-point exception",			"SIGFPE"},
	{SIGCHLD,	"Child status has changed",			"SIGCHLD"},
	{-1,		NULL,						NULL}
 };

 extern sig_atomic_t signaled;

 static int
 LogSignal(struct Session *s, pid_t pid, int status)
 {
	pid_t       parent;
	struct Map *map;
	char       *filename = "No dump";

 	#ifdef PTRACE
	siginfo_t siginfo;
	char *msg = NULL;
	struct user_regs_struct regs;

	assert((parent = GetProcessParent(s->process, pid)) != -1);
	#else
	parent = pid;
	#endif

	assert((map = GetMapByPid(s->maps, parent)) != NULL);

	if(s->dump)
	{
		if(!(filename = GetFilename(s->output, map)))
		{
			fprintf(s->logfile, "[!] out of memory?\n");
			return -1;
		}

		DumpMap(s, map, filename);
		
		if(s->detail)
		{
			fprintf(s->logfile, "[i] Filename:       %s\n", filename);
		}
		else
		{
			fprintf(s->logfile, "filename=%s,\n", filename);
		}

		free(filename);
	}

	if(s->detail)
	{
		fprintf(s->logfile, "[i] Signal:         %s\n", strsignal(WTERMSIG(status)));
		fprintf(s->logfile, "[i] Fuzzing string: %d\tOffset: %d\n", map->fuzzn, map->byten);
	}
	else
	{
		/*
		 * We did not dump the map, here you have all the info to digest and 
		 * use replay.py to get the map
		 */
		#ifdef PTRACE
		fprintf(s->logfile, "signal=%s,fuzzn=%d,byten=%d",
			strsignal(WSTOPSIG(status)), map->fuzzn, map->byten);
		#else
		fprintf(s->logfile, "signal=%s,fuzzn=%d,byten=%d\n",
			strsignal(WTERMSIG(status)), map->fuzzn, map->byten);
		#endif
	}
	
	#ifdef PTRACE
	if(ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo) == -1)
	{
		perror("print_siginfo::ptrace(PTRACE_GETSIGINFO)");
		return -1;
	}

	switch(WSTOPSIG(status))
	{
		case SIGABRT:
		{
			msg = "aborted";
			break;	
		}
		case SIGILL:
		{
			switch(siginfo.si_code)
			{
				case ILL_ILLOPC:
					msg = "illegal opcode";
					break;
				case ILL_ILLOPN:
					msg = "illegal operand";
					break;
				case ILL_ILLTRP:
					msg = "illegal trap";
					break;
				case ILL_PRVOPC:
					msg = "privileged opcode";
					break;
				case ILL_PRVREG:
					msg = "privileged register";
					break;
				case ILL_COPROC:
					msg = "coprocessor error";
					break;
				case ILL_BADSTK:
					msg = "internal stack error";
					break;
			}

			break;
		}
		case SIGSEGV:
		{
			switch(siginfo.si_code)
			{
				case SEGV_MAPERR:
					msg = "address not mapped to object";
					break;
				case SEGV_ACCERR:
					msg = "invalid permissions for mapped object";
					break;
			}

			break;
		}
		case SIGFPE:
		{
			switch(siginfo.si_code)
			{
				case FPE_INTDIV:
					msg = "integer divide by zero";
					break;
				case FPE_INTOVF:
					msg = "integer overflow ";
					break;
				case FPE_FLTDIV:
					msg = "floating point divide by zero";
					break;
				case FPE_FLTOVF:
					msg = "floating point overflow";
					break;
				case FPE_FLTUND:
					msg = "floating point underflow";
					break;
				case FPE_FLTRES:
					msg = "floating point inexact result";
					break;
				case FPE_FLTINV:
					msg = "floating point invalid operation";
					break;
				case FPE_FLTSUB:
					msg = "subscript out of range";
					break;
			}

			break;
		}
		case SIGBUS:
		{
			switch(siginfo.si_code)
			{
				case BUS_ADRALN:
					msg = "invalid address alignment";
					break;
				case BUS_ADRERR:
					msg = "non-existent physical address";
					break;
				case BUS_OBJERR:
					msg = "object specific hardware error";
					break;
			}

			break;
		}
	}

	if(GetGeneralRegisters(pid, &regs) == -1)
	{
		return -1;
	}

	if(s->detail)
	{
		fprintf(s->logfile, "[i] Detail:   %s - Address of exception: %p\n",
			msg, siginfo.si_addr);
		
		/* Print detailed information about the exceptional condition. */
	
		PrintGeneralRegisters (s->logfile, regs);
		PrintStackFrame       (s->logfile, pid, regs);
		PrintDisassembly      (s->logfile, pid, regs);
		
		fprintf (s->logfile, LINE);
	}
	else
	{
		fprintf(s->logfile, ",address=%p,eip=0x%.8lx\n", siginfo.si_addr, regs.eip);	
	}
	#endif
	
	return 0;
 }

 #ifdef PTRACE
 int
 WaitForSignal(struct Session *s)
 {
	pid_t 	pid 	 = 0;
	pid_t 	parent	 = 0;
	pid_t   childpid = 0;
	int 	status	 = 0;
	int	sig	 = 0;

	struct  Process *tmp;
	struct  Child   *child;
	struct  Map     *map;
	
	if(((pid = waitpid(-1, &status, 0)) == -1) && (errno == ECHILD))
	{
		return 0;
	}

	if(WIFEXITED(status) || WIFSIGNALED(status))
	{
		/* What if it does not have a parent ? */
		if((parent = GetProcessParent(s->process, pid)) == -1)
		{
			fprintf(stderr, "[e] PID = %d has no parent and its not on our pid list\n", pid);
			return -1;
		}
		
		assert(SetProcessStatus(s->process, parent, pid, STATUS_DEAD) != -1);

		/* process ran out of descendants */
		if(!HasChilds(s->process, parent))
		{
			/* free resources */
			assert((map = GetMapByPid(s->maps, parent)) != NULL);
			SetFree(map);
			
			RemoveParent(&(s->process), parent);
			DEC_PROC_COUNT(s);
		}

		#ifdef DEBUG
		{
			if(parent == pid)
				fprintf(stderr, "[DEBUG] PARENT  destroyed [%d] ", pid);	
			else
				fprintf(stderr, "[DEBUG] CHILD   destroyed [%d] ", pid);
				
			if(WIFEXITED(status))
		    	fprintf(stderr, "throwed %s\n", strsignal(WTERMSIG(status)));
			else
		    	fprintf(stderr, "exited with %d\n", WEXITSTATUS(status));
		}
		#endif
	}
	else if(WIFSTOPPED(status))
	{
		sig = WSTOPSIG(status);
		
		#ifdef DEBUG1
			fprintf(stderr, "[DEBUG] PROCESS STOPPED   [%d] and throwed %s\n",
  			pid, strsignal(sig));
		#endif

		switch(sig)
		{
			case SIGUSR1:
			{
				/*
				 * The child its being synchonized
				 */
				
				if(ptrace(PTRACE_SETOPTIONS, pid, NULL,
					PTRACE_O_TRACESYSGOOD |
					PTRACE_O_TRACEFORK |
					PTRACE_O_TRACEVFORK|
					PTRACE_O_TRACECLONE) == -1)
				{
					perror("WaitChild::ptrace(PTRACE_SETOPTIONS)");
					exit(-1);
				}

				break;
			}
			case SIGTRAP:
			{
				/* 
				 * Maybe a DEBUG EVENT (fork, vfork, execve, etc)
				 */

				switch((status >> 16) & 0xffff)
				{
					case PTRACE_EVENT_CLONE:
					case PTRACE_EVENT_FORK:
					case PTRACE_EVENT_VFORK:
					{
						if(ptrace(PTRACE_GETEVENTMSG, pid, 0, &childpid) == -1)
						{
							perror("print_siginfo::ptrace(PTRACE_GETEVENTMSG)");
							return -1;
						}
					
						assert((parent = GetProcessParent(s->process, pid)) != -1);
						
						AddChildProcess(s->process, parent, childpid);
						
						#ifdef DEBUG
						fprintf(stderr, "[DEBUG] PARENT  CREATED   [%d] child [%d]\n",
						parent, childpid);	
						#endif

						break;
					}
				}
				
				break;
			}
			case SIGALRM:
			{
				/*
				 * Process timed out
				 */
				
				parent = GetProcessParent(s->process, pid);
				if((parent != pid) || (parent == -1))
				{
					/* We need to continue this SIGNAL */
					break;
				}

				/* Kill all the running childrens */				
				for(tmp = s->process; tmp; tmp = tmp->next)
				{
					if(tmp->pid == pid)
					{
						for(child = tmp->childs; child; child = child->next)
						{
							if(child->status == STATUS_RUN)
							{
								#ifdef DEBUG
								fprintf(stderr, "[DEBUG] KILL    CHILD     [%d]\n", child->pid);
								#endif
								
								if(ptrace(PTRACE_KILL, child->pid, NULL, 0) == -1)
								{
									perror("WaitChild::ptrace(PTRACE_KILL)");
									return -1;
								}
							}
						}
						
						break;
					}
				}

				/* Kill the parent */
				if(ptrace(PTRACE_KILL, parent, NULL, 0) == -1)
				{
					perror("WaitChild::ptrace(PTRACE_KILL)");
					return -1;
				}

				/* There is no need to continue any signal */
				return 1;
				break;
			}
			case SIGABRT:	/* Important for heap stuff */
			case SIGILL:
			case SIGSEGV:
			case SIGFPE:
			case SIGBUS:
			{
				LogSignal(s, pid, status);
				ADD_BUG(s);

				break;
			}
		}

		if(ptrace(PTRACE_CONT, pid, 0, 
			(sig == SIGTRAP || sig == SIGSTOP || sig == SIGUSR1) ? 0 : sig) == -1)
		{
			perror("WaitChild::ptrace(PTRACE_CONT)");
			exit(-1);
		}
	}
	
	return 1;
 }
 
 #else /* PTRACE */
 
 int
 WaitForSignal(struct Session *s)
 {
 	struct  Map *map = NULL;
	pid_t 	pid 	 = 0;
	int 	status	 = 0;
	int	sig	 = 0;
	
	if((pid = waitpid(-1, &status, 0)) == -1 && (errno == ECHILD))
	{
		return 0;
	}

	if(WIFEXITED(status))
	{
		#ifdef DEBUG1
		{
		  if(WIFEXITED(status))
		  {
		    fprintf(stderr, "[DEBUG] Child %d exited with %d\n", pid,
		    	WEXITSTATUS(status));
		  }
		}
		#endif
	}
	else if(WIFSIGNALED(status))
	{
		sig = WTERMSIG(status);
		
		#ifdef DEBUG1
		{ 
		    fprintf(stderr, "[DEBUG] Child %d throwed %s\n", pid,
		    	strsignal(sig));
		}
		#endif
		
		switch(sig)
		{
			case SIGALRM:
			{	
				kill(-1*pid, SIGKILL);
				break;	
			}
			default:
			{
				LogSignal(s, pid, status);
				ADD_BUG(s);

				break;
			}
		}
	}
	
	/* TODO: This might be wrong, see what happens when a process throws a signal
		 that is not handled here and does not kill the process
	*/

	assert((map = GetMapByPid(s->maps, pid)) != NULL);
	SetFree(map);
	DEC_PROC_COUNT(s);	

	return 1;
 }

 #endif /* PTRACE */

 int
 RegisterHandlers()
 {
	struct   sigaction sa_interrupt;
	sigset_t blocked;
	
	if(signal(SIGQUIT, SIG_IGN) == SIG_ERR || signal(SIGTERM, SIG_IGN) == SIG_ERR)
	{
		perror("[!] RegisterHandlers::signal");
		return -1;
	}
	
	sigemptyset(&blocked);
	
	sa_interrupt.sa_handler = InterruptHandler;
	sa_interrupt.sa_mask    = blocked;	
	sa_interrupt.sa_flags   = SA_NOCLDSTOP | SA_RESTART;
	
	if(sigaction(SIGINT, &sa_interrupt, NULL) == -1)
	{
		perror("[!] RegisterHandlers::sigaction");
		return -1;
	}

	return 0;
 }

 char *
 Sig2Str(int signal)
 {
	int i = 0;
	 
	while(signals[i].signal != -1)
	{
		if(signals[i].signal == signal)
		{
			return signals[i].description;	
		}
		else
		{
			i++;
		}
	}
	
	return NULL;
 }

 int
 Str2Sig(char *name)
 {
	int i = 0;
	 
	while(signals[i].signal != -1)
	{
		if(strncmp(signals[i].name, name, strlen(name)) == 0)
		{
			fprintf(stdout, "Killing signal: %s\n", signals[i].description);
			return signals[i].signal;
		}
		
		i++;
	}
	
	return -1;
 }

 void
 InterruptHandler(int signum)
 {
	 signaled = TRUE;
 }
