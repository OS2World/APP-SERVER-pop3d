/*
 *	pop3d		- IP/TCP/POP3 server for UNIX 4.3BSD
 *			  Post Office Protocol - Version 3 (RFC1225)
 *
 *      (C) Copyright 1991 Regents of the University of California
 *
 *      Permission to use, copy, modify, and distribute this program
 *      for any purpose and without fee is hereby granted, provided
 *      that this copyright and permission notice appear on all copies
 *      and supporting documentation, the name of University of California
 *      not be used in advertising or publicity pertaining to distribution
 *      of the program without specific prior permission, and notice be
 *      given in supporting documentation that copying and distribution is
 *      by permission of the University of California.
 *      The University of California makes no representations about
 *      the suitability of this software for any purpose.  It is provided
 *      "as is" without express or implied warranty.
 *
 *	Katie Stevens
 *	dkstevens@ucdavis.edu
 * 	Information Technology -- Campus Access Point
 *	University of California, Davis
 *
 **************************************
 *
 *	pop3.h
 *
 *	REVISIONS:
 *		02-27-90 [ks]	original implementation
 *	1.000	03-04-90 [ks]
 *	1.001	06-24-90 [ks]	allow TRANS state if 0 msgs in folder
 *				implement optional TOP command
 *	1.002	07-22-91 [ks]	-- reset index counter after folder rewind
 *				   in fld_release (Thanks to John Briggs,
 *				   Vitro Corporation, Silver Spring, MD
 *				   for finding this bug!)
 *				-- set umask() value explicitly (Thanks to
 *				   Vikas Aggarwal, JvNCnet, Princeton, NJ
 *				   for suggesting this)
 *				-- remove unnecessary 'return' at end
 *				   of void functions
 *	1.003	03-92    [ks]	close folder before return from main()
 *	1.004   11-13-91 [ks]	leave original mailbox intact during POP
 *				session (Thanks to Dave Cooley,
 *				dwcooley@colby.edu, for suggesting this)
 *	1.005	01-04-96 [dts]	change mktemp to mkstemp to avoid security
 *				hole with mktemp (timing attack).
 *
 *	1.010	05-31-99 [avl]	First port for OS/2 + EMX.
 *
 *	(See header of main.c for current revision info.)
 */

#define VERSION		"1.010 - OS/2"
#define REVDATE		"May 31 1999"

/* In main.c: */
extern void fail();

/* Server functions (server.c) */
extern int svr_auth(int state, char *inbuf);
extern int svr_pass(int state, char *inbuf);
extern int svr_trans(int state, char *inbuf);
extern int svr_fold(int state, char *inbuf);
extern int svr_shutdown();
extern void svr_abort(int err_code);
extern void svr_data_in(char *buf);
extern void svr_data_out(char *buf);

/* Folder functions (folder.c) */
extern int fld_fromsp();

extern void fld_delete(int msgnum);
extern void fld_last();
extern void fld_list(int msgnum);
extern void fld_uidl(int msgnum);
extern void fld_reset();
extern void fld_retr(int msgnum, int linecnt);
extern void fld_stat();

extern void fld_release();

#define xfree(p)	{ if( (p) != NULL ) free(p); (p) = NULL; }
/* In util.c: */
inline void *xmalloc(size_t size);
inline void *xstrdup(char *string);
void xsyslog(int pri, const char *fmt, ...);

extern char *apop_timestamp();
extern char *fgetl(char *buf, int n, FILE *fp);
extern void cmd_prepare(char *cmd);
extern char *get_fdqn();
/* Semaphors support */
extern unsigned long sem_create(char *name);
extern void sem_post(char *name);
extern void sem_reset(unsigned long handler);
extern void sem_wait(unsigned long handler);
extern void sem_close(unsigned long handler);

/* In user.c: */
extern int verify_user(char *user, char *pass);
extern int verify_user_apop(char *user, char *pass);

/* In md5.c */
extern void do_md5_file(FILE *src, long start, long end, char *hash);
extern void do_md5_string(char *pass, int passlen, char *hash);

#define	TCP_SERV_PORT		110

#define SVR_LISTEN_STATE	0x00		/* Wait for client connection */
#define SVR_AUTH_STATE		0x01		/* Expecting USER command */
#define SVR_PASS_STATE		0x02		/* Expecting PASS command */
#define SVR_TRANS_STATE		0x03		/* Process mailbox commands */
#define SVR_FOLD_STATE		0x04		/* Need to open another mbox */
#define SVR_DONE_STATE		-1

#define SVR_TIMEOUT_CLI		600		/* 10 minutes */
#define SVR_TIMEOUT_SEND	120		/* 02 minutes */
#define SVR_BUFSIZ		512
#define CLI_BUFSIZ		128
#define	MAXSTR			128

#define LOGFILE			"/pop3d.log"
#define APOP_PASSWORD_FILE	"/apop.cnf"	/* file of *unencrypted* passwords */
#define POP3D_PASSWORD_FILE	"/passwd"	/* file of encrypted passwords */
#define MAILADDR_FILE		"/mailaddr"	/* old style user info file */

#define POP3_RCPT_HDR		"X-POP3-Rcpt:"

#define FAIL_CONFUSION		51		/* unknown error */
#define FAIL_FILE_ERROR		52		/* file read/write error */
#define FAIL_HANGUP		53		/* client hung up on us */
#define FAIL_LOST_CLIENT	54		/* timeout waiting for client */
#define FAIL_OUT_OF_MEMORY	55		/* out of system memory */
#define FAIL_PROGERR		56		/* unexpected program error */
#define FAIL_PIPE		57		/* DTS 28Jul96 - usually */
						/*     while sending a msg */
#define FAIL_INTERRUPT		58		/* unhandled signal */
#define FAIL_SOCKET_ERROR	59		/* socket read/write error */

#define NULL_CHAR	'\0'
#define LF_CHAR		'\n'
#define CR_CHAR		'\r'
#define DOT_CHAR	'.'
#define LANKLE_CHAR	'<'
#define RANKLE_CHAR	'>'

#ifndef min
#define min(a, b)	((a) < (b) ? (a) : (b))
#endif

#define SYSLOGPRI	(LOG_MAIL | LOG_INFO)

/* DTS 01Jul98 - added delay before returning failed pass notice to
 *	slow/prevent guessing attacks
 */
#define FAILPASS_DELAY	5

#define MSG_DELETED	0x01		/* Msg marked for deletion */
#define MSG_UNAVAILABLE	0x02		/* Msg deleted by other process */

typedef struct fld_item {
	char *file_name;		/* Name of the file with msg */
	time_t mtime;			/* Time of the file creation */
	long bcount;			/* #bytes this msg (for scan listing) */
	long count;			/* #bytes this msg (for UIDL purposes) */
	int status;			/* Status of this message */
	char *id;			/* Unique ID of msg */
} t_fld_item;


