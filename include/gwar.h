/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _GWAR_H
#define _GWAR_H

#ifdef __cplusplus	
extern "C"
{
#endif

	/* used in linked lists */
	#define NEXT_ITEM(x)		(x->next)
	#define INC_PROC_COUNT(x)	(x->currentprocs++)
	#define DEC_PROC_COUNT(x)	(x->currentprocs--)
	#define FUZZING_LIST(x)		(x->f)
	#define LOOKUP_LIST(x)		(x->l)
	#define DATAFIELD_LIST(x)	(x->d)
	#define ADD_BUG(x)		((x->bugs)++)
	
	#define MODE_SMART 0
	#define MODE_BRUTE 1
	#define MODE_ASCII 2
	
	#define FALSE 0
	#define TRUE  1

	struct Range
	{
		u_int low;
		u_int high;
	};

	struct Session
	{
		u_int   exec;
		u_int   skipped;
		
		u_int   gen;
		off_t   byte;		/* fuzzing byte */
		u_int   timeout;
		u_int   maxproc;
		u_int   skipfuzz;
		u_int   fuzzcount;	/* fuzzing variable counter */
		u_int   headercount;
		u_int   currentprocs;
		
		#ifdef PTRACE
			struct Process *process;
			u_short followfork;
		#endif

		u_short dump;		
		u_short detail;
		u_short dontkill;
		u_short restore;
		u_short closefd;
		u_short logfd;
		off_t   filesize;
		int     killsignum;
		int     bugs;
		int     mode;
		int     index;	/* index inside s->argv to "%%FILENAME%%" */
		char   *output;
		char   *extension;
		char   *input;
		char   *command;
		char   *headers;
		char  **argv;
		char  **envp;
		char   *logfilename;
		char   *progname;
		FILE   *logfile;

		struct fuzzes		*curfuzz;	/* the "actual" fuzzing string */
		struct DataField	*curfield;	/* the "actual" data field */

		struct Map *maps;

		struct Range      range;
		struct fuzzes    *f;
		struct DataField *d;
			
	};

#ifdef __cplusplus
}
#endif

#endif				/* _GWAR_H */
