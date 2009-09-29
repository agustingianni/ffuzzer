#ifndef PROCESS_H_
#define PROCESS_H_

struct Child
{
	pid_t			pid;
	int				status;
	struct Child 	*next;
};

struct Process
{
	pid_t pid;
	u_int fuzzno;
	u_int byteno;
	int	  status;
	
	struct Child 	*childs;
	struct Process 	*next;
};

#define STATUS_INVALID -1
#define STATUS_RUN      0
#define STATUS_DEAD     1

int   SetProcessStatus   (struct Process *,  pid_t, pid_t, int);
int   HasChilds          (struct Process *,  pid_t);
pid_t GetProcessParent   (struct Process *,  pid_t);
int   AddParentProcess   (struct Process **, pid_t);
int   RemoveParent       (struct Process **, pid_t);
int   GetProcessStatus   (struct Process *,  pid_t, pid_t);
int   AddChildProcess    (struct Process *,  pid_t, pid_t);
int   RemoveChildProcess (struct Process *,  pid_t, pid_t);


#endif /*PROCESS_H_*/
