#ifndef MAPPINGS_H_
#define MAPPINGS_H_

struct Map
{
	int    fuzzn;
	int    byten;

	char  *name;
	void  *address;		/* Address of the file mapping */
	char   inuse;		/* Is in use? */
	short  id;		/* Unique ID */
	pid_t  pid;		/* Map is being used by pid */
	size_t size;		/* initial Size of the map */
	size_t currsize;	/* Current size of the map */
	struct Map *next;	/* Next Map */
};

#define is_free(m)		((m->inuse == 0))
#define set_inuse(m)	(m->inuse = 1)
#define set_free(m)		(m->inuse = 0)
#define set_mappid(m,p)	(m->pid   = p)
#define set_id(m,i) 	(m->id    = i)
#define get_id(m)		(m->id)

#define SetUniqueID(m, f, b)	\
	m->fuzzn = f;		\
	m->byten = b;

inline void SetInUse		(struct Map *);
inline void SetFree		(struct Map *);
inline void SetMapPid		(struct Map *, pid_t);

struct Map *GetFreeMap		(struct Map *);
struct Map *CreateBackupMap	(char *);
struct Map *GetMapByPid		(struct Map *, pid_t);
char       *GetFilename		(char *, struct Map *);
int         CopyFile		(char *, char *);

int    SyncFileMap		(struct Map *);
int    RefreshMaps		(struct Map *, struct Map *);
int    FreeMaps			(struct Map *);
int    PrintMapNames		(struct Map *);
char   *GetMapName		(struct Map *, char *);

int    CreateMaps		(struct Session *, unsigned int);
int    DumpMap			(struct Session *, struct Map *, char *);
int    InsertFuzzingString	(struct Session *, struct Map *, struct Map *);

#endif /*MAPPINGS_H_*/
