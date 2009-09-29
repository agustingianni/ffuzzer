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

#ifndef _SIGNALS_H
#define _SIGNALS_H

#ifdef __cplusplus
extern "C"
{
#endif

	#define LINE "_________________________________________________________________________________________\n"

	#define WaitChilds(x) while(WaitForSignal(x))

	int  Str2Sig (char *);
	void InterruptHandler (int);
	int  eval_signal (int, pid_t);
	int  RegisterHandlers();
	int  OldWaitChild(struct Session *);
	int  WaitForSignal(struct Session *);
    char *Sig2Str(int);
	
	struct Signals
	{
		int signal;
		char *description;
		char *name;
	};

#ifdef __cplusplus
}
#endif

#endif				/* _SIGNALS_H */
