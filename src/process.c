#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "process.h"

/* 
 * Returns the parent pid of a given pid, if it does not have
 * a parent, then pid == parent
 */
pid_t 
GetProcessParent(struct Process *p, pid_t pid)
{
	struct Process *ptemp;
	struct Child   *ctemp;
	
	for(ptemp = p; ptemp ; ptemp = ptemp->next)
	{
		if(ptemp->pid == pid)
		{
			return pid;	
		}
		
		for(ctemp = ptemp->childs; ctemp; ctemp = ctemp->next)
		{
			if(ctemp->pid == pid)
			{
				return ptemp->pid;	
			}
		}
	}
	
	return -1;
}

/* WORKING */
int
AddParentProcess(struct Process **p, pid_t pid)
{
	struct Process *newprocess = (struct Process *) calloc(1, sizeof(struct Process));
	
	if(!newprocess)
	{
		perror("AddParentPRocess::malloc()");
		return -1;
	}
	
	newprocess->pid    = pid;
	newprocess->next   = *p;
	newprocess->status = STATUS_RUN;
	*p = newprocess;
	
	#ifdef DEBUG2
	fprintf(stdout, "[DEBUG] Added parent pid %d\n", pid);
	#endif
	
	return 0;
}

/* MIGHT BE WORKING */
int
AddChildProcess(struct Process *p, pid_t parent, pid_t child)
{
	struct Process *temp;
	struct Child   *newchild;
	int err = -1;
	
	for(temp = p; temp; temp = temp->next)
	{
		if(temp->pid == parent)
		{
			newchild = (struct Child *) calloc(1, sizeof(struct Child));
			
			if(!newchild)
			{
				perror("AddChildProcess::malloc()");
				return -1;	
			}
	
			newchild->pid 	 = child;
			newchild->next 	 = temp->childs;
			newchild->status = STATUS_RUN;
			temp->childs 	 = newchild;
	
			err = 0;
		}
	}
	
	#ifdef DEBUG2
	fprintf(stdout, "[DEBUG] Added child pid %d - Parent pid %d\n", child, parent);
	#endif
	
	return err;
}

int
RemoveParent(struct Process **p, pid_t pid)
{
	struct Process 	*temp, *prev;
	struct Child 	*c;
	int    err = -1;

	prev = NULL;
	
	for(temp = *p; temp; temp = temp->next)
	{
		if(temp->pid == pid)
		{
			while(temp->childs)
			{
				c = temp->childs->next;
				free(temp->childs);
				temp->childs = c;
			}
			
			if(prev)
			{
				prev->next = temp->next;
			}
			else
			{
				*p = temp->next;
			}

			free(temp);
			err = 0;

			break;
		}
		else
		{
			prev = temp;
		}
	}
	
	#ifdef DEBUG2
	fprintf(stdout, "[DEBUG] removed parent pid %d\n", pid);
	#endif
	
	return err;
}

int
SetProcessStatus(struct Process *p, pid_t parent, pid_t pid, int status)
{
	struct Process *tmp;
	struct Child   *cld;
	
	int ret = STATUS_INVALID;
	
	for(tmp = p; tmp; tmp = tmp->next)
	{
		if(tmp->pid == parent)
		{
			if(parent == pid)
			{
				tmp->status = status;
				ret = status;
				break;				
			}
			
			for(cld = tmp->childs; cld; cld = cld->next)
			{
				if(cld->pid == pid)
				{
					cld->status = status;
					ret = status;
					break;			
				}				
			}
			
			break;
		}
	}	
	
	return ret;
}

int
GetProcessStatus(struct Process *p, pid_t parent, pid_t pid)
{
	struct Process *tmp;
	struct Child   *cld;
	
	int status = STATUS_INVALID;
	
	for(tmp = p; tmp; tmp = tmp->next)
	{
		if(tmp->pid == parent)
		{
			if(tmp->pid == pid)
			{
				status = tmp->status;
				break;				
			}
			
			for(cld = tmp->childs; cld; cld = cld->next)
			{
				if(cld->pid == pid)
				{
					status = cld->status;
					break;			
				}				
			}
			
			break;
		}
	}	
	
	return status;
}

int
HasChilds(struct Process *p, pid_t parent)
{
	struct Process 	*temp;
	struct Child 	*c;
	int ret = 0;
	
	for(temp = p; temp; temp = temp->next)
	{
		if(temp->pid == parent)
		{
			for(c = temp->childs; c ; c = c->next)
			{
				if(c->status == STATUS_RUN)
				{
					ret = 1;
					break;
				}
			}
			
			break;
		}
	}
	
	return ret;	
}

int
RemoveChildProcess(struct Process *p, pid_t parent, pid_t child)
{
	struct Process 	*temp;
	struct Child 	*c;
	int ret = -1;
	
	for(temp = p; temp; temp = temp->next)
	{
		if(temp->pid == parent)
		{
			for(c = temp->childs; c ; c = c->next)
			{
				if(c->pid == child)
				{
					ret = 0;
					c->pid = -1;
					break;
				}
			}
			
			break;
		}
	}
	
	#ifdef DEBUG2
	fprintf(stdout, "[DEBUG] Removed child pid %d - Parent pid %d\n", child, parent);
	#endif
	return ret;
	
}
