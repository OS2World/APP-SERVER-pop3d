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
 *	main.c
 *
 *	REVISIONS:
 *		02-27-90 [ks]	original implementation
 *	1.000	03-04-90 [ks]
 *	1.001	06-24-90 [ks]	implement optional TOP command
 *	1.002	07-22-91 [ks]	-- reset index counter after folder rewind
 *				   in fld_release (Thanks to John Briggs,
 *				   vaxs09@vitro.com, Vitro Corporation,
 *				   Silver Spring, MD for finding this bug!)
 *				-- set umask() value explicitly (Thanks to
 *				   Vikas Aggarwal, JvNCnet, Princeton, NJ
 *				   for suggesting this)
 *	1.003	03-92    [ks]   close mailbox before return from main()
 *	1.004   11-13-91 [ks]	leave original mailbox intact during POP
 *				session (Thanks to Dave Cooley,
 *				dwcooley@colby.edu for suggesting this)
 *	1.005a	01-04-96 [dts]	change mktemp to mkstemp to avoid security
 *				hole with mktemp (timing attack).
 *	1.005b	02-14-96 [dts]	added syslogging success and failed attempts
 *	1.005c	07-28-96 [dts]	added some debug and catch for SIGPIPE that
 *				   aborted downloads were causing (leaving files
 *				   in /tmp.
 *	1.005d	10-20-96 [dts]	changed to use "named" temp files so subsequently
 *				   called pop3d's would find them and exit
 *				   immediately and not do lots of copying
 *				   Deleted "host" and "mbox" non-POP3 commands.
 *				   Deleted all BSMTP mailbox stuff.
 *				   Added "-d" argv for debugging from inetd.conf
 *	1.005e	01-19-97 [dts]	Added bug fixes from Henrik Seidel for the TOP
 *				    command in main.c folder.c.
 *	1.005f	04-27-97 [dts]	Added code to strip "@domian" from username.
 *				Changed strcpy to strncpy due to note on bugtraq
 *	1.005g	04-28-97 [dts]	Released 1.005f, started 1.005g
 *		04-28-97 [dts]  Created the valid.c routine and removed the
 *				old shadow.h & valid.o which had no source!
 *		04-29-97 [dts]	Added patch to util.c for /etc/passwd use even
 *				with shadow - set file for credits.
 *	1.005h	04-29-97 [dts]	Released 1.005g, started 1.005h
 *	1.005i	06-23-97 [dts]	added TACACS patch, began work on VIRTUAL
 *	1.005j	07-10-97 [dts]	added patch to do md5 sums for UIDL (fix for
 * 				Eudora problem.
 *
 *	1.010	05-31-99 [avl]	First port for OS/2 + EMX.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <io.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <errno.h>

#include "pop3.h"

/* Process */
FILE	*logfp = NULL;			/* File for recording session */
int	debug = 0;
int	use_syslog = 0;
int	mypid;
char	*svr_hostname = 0;			/* Hostname of POP3 server */

/* Connection */
char *client_ip = 0;			/* Client IP address */
char *user_name = 0;			/* Save client username */
char *timestamp = 0;			/* Timestamp for connection */
char *user_mailbox = 0;			/* Name of mailbox directory */
char *svr_buf = 0;			/* Buffer for server output */

int  pass_delay = 0;			/* Delay after invalid user/password */

/* Routines in this file */
static void initialize();
static void setsigs();
static void svr_catchint(int);	/* DTS 28Jul96 */
static void svr_timeout();
static void int_hangup();
static void int_progerr();
static void int_pipe();		/* DTS 28Jul96 */

static int parse_opts(int argc, char *argv[]);

#ifdef VIRTUAL
extern int virtual_mode;
extern char *virt_spooldir;
extern char *virt_workdir;
#endif

/**************************************************************************/

/* Initialize POP3 server */
static void
initialize()
{
	char buf[MAXSTR];
	char *p;
	struct sockaddr_in addr;
	int addr_len = sizeof(struct sockaddr_in);

	mypid = getpid();
	timestamp = apop_timestamp();
	if ( debug ) {
		/* Prepare log file */
		p = getenv("ETC");
		if (p != NULL)
			strcpy(buf, p);
		strcat(buf, LOGFILE);
		logfp = fopen(buf, "a+");	/* DTS to let accumulate */
		if(logfp == NULL)
			logfp = stderr;
		fprintf(logfp, "[%d] POP3 server startup; version %s %s\n",
			mypid, VERSION, timestamp);
		fflush(logfp);
	}

	/* Get our hostname */
	gethostname(buf, MAXSTR);
	svr_hostname = xstrdup(buf);

	getpeername(STDIN_FILENO, (struct sockaddr *) &addr, &addr_len);
	client_ip = xstrdup(inet_ntoa(addr.sin_addr));

	svr_buf = (char *) xmalloc(SVR_BUFSIZ);
	user_name = (char *) xmalloc(CLI_BUFSIZ);

	setsigs();
}

void
setsigs()
{
	int	i;		/* DTS 28Jul96 */

	/* DTS 28Jul96 add loop to set all sigs to be caught and logged */
	for( i=0; i<NSIG; i++) {
		signal(i, svr_catchint);
	}
	/* and now let the following override certain ones... */

	/* Handle process signals ourself */
	signal(SIGALRM, svr_timeout);		/* timer expiration */

	signal(SIGHUP, int_hangup);		/* interrupt signals */
	signal(SIGTERM, int_hangup);
	signal(SIGINT, int_hangup);
	signal(SIGQUIT, int_hangup);

	signal(SIGSEGV, int_progerr);
	signal(SIGILL, int_progerr);
	/* DTS 28Jul96 - SIGPIPE Netscape caused when "stopping" a message
	 *	usually caught while looping and sending a long message
	 */
	signal(SIGPIPE, int_pipe);
}

/* DTS added 28Jul96 to help debugging */
static void
svr_catchint(int sig)
{
	svr_abort(FAIL_INTERRUPT);			/* Exit POP3 server */
}
	
/* Timeout while waiting for next client command */
static void
svr_timeout()
{
	svr_abort(FAIL_LOST_CLIENT);			/* Exit POP3 server */
}
/* Timeout while waiting for next client command */
static void
int_hangup()
{
	svr_abort(FAIL_HANGUP);				/* Exit POP3 server */
}
/* Timeout while waiting for next client command */
static void
int_progerr()
{
	svr_abort(FAIL_PROGERR);			/* Exit POP3 server */
}
/* Signal recieved usually while sending message (due to "Stop" a message) */
/* DTS 28Jul96 */
static void
int_pipe()
{
	svr_abort(FAIL_PIPE);				/* Exit POP3 server */
}

void mem_free()
{
	xfree(svr_hostname);
	xfree(client_ip);
	xfree(user_name);
	xfree(timestamp);
	xfree(user_mailbox);
	xfree(svr_buf);
}

/**************************************************************************/

/* DTS added args 14Feb96 for sysloging*/
/* DTS 23Mar98 changed to inetd_main from main to test standalone server */
#ifdef STANDALONE
int
inetd_main( int argc, char *argv[])
#else
int
main( int argc, char *argv[])
#endif
{
	int svr_state = SVR_LISTEN_STATE;	/* State of POP3 server */
	char cli_buf[CLI_BUFSIZ];		/* Buffer for client cmds */
	int socket_fd;

	socket_fd = parse_opts(argc, argv);
	if(socket_fd > 0) {
		socket_fd = _impsockhandle(socket_fd, 0);
		if (socket_fd < 0)
			fail(FAIL_SOCKET_ERROR);
		dup2(socket_fd, 0);
		dup2(socket_fd, 1);
		close(socket_fd);
	}
#ifdef STANDALONE
	sem_post(argv[0]);
#endif
	initialize();

	/* DTS added 14Feb96 for sysloging (should it be AUTHPRIV or MAIL?) */
	if ( use_syslog )
		openlog( argv[0], LOG_PID, LOG_MAIL );

#ifdef VIRTUAL
	/* DTS 23Jun97 added VIRTUAL */
	virt_init();
#endif

	sprintf(svr_buf, "+OK %s POP3 Server (Ver. %s) ready %s\r\n",
		svr_hostname, VERSION, timestamp);
	svr_data_out(svr_buf);
	svr_state = SVR_AUTH_STATE;
	for ( ; ; ) {
		/* Wait for command from client */
		svr_data_in(cli_buf);

		/* Take action on client command */
		cmd_prepare(cli_buf);
		if ( debug ) {
			if (cli_buf[0] == 'p' || cli_buf[0] == 'P')
				fprintf(logfp, "[%d] CLI: PASS\n", mypid);
			else
				fprintf(logfp, "[%d] CLI: %s\n", mypid, cli_buf);
			fflush(logfp);
		}
		switch(svr_state) {
		case SVR_AUTH_STATE:	/* Expecting USER or APOP command */
			svr_state = svr_auth(svr_state, cli_buf);
			break;
		case SVR_PASS_STATE:	/* Expecting PASS command */
			svr_state = svr_pass(svr_state, cli_buf);
			break;
		case SVR_TRANS_STATE:	/* Expecting mailbox command */
			svr_state = svr_trans(svr_state, cli_buf);
			break;
		case SVR_FOLD_STATE:	/* Need to open another mailbox */
			svr_state = svr_fold(svr_state, cli_buf);
			break;
		default:
			svr_abort(FAIL_CONFUSION);		/* Wont return */
		}

		if ( debug ) {
			fprintf(logfp, "[%d] SVR: %s", mypid, svr_buf);
			fflush(logfp);
		}

		/* Send out response to client */
		svr_data_out(svr_buf);

		if( pass_delay ) {
			sleep(FAILPASS_DELAY);	/* DTS 01Jul98 - to prevent guessing attacks */
			pass_delay = 0;
		}
		/* Exit when server has sent goodbye */
		if (svr_state == SVR_DONE_STATE)
			break;
	}
	mem_free();
	close(0);
	close(1);
	exit(0);
}

/* Send an error message and exit POP3 server */
void
fail(int  err)
{
	char *cp;

	switch(err) {
	case FAIL_INTERRUPT:			/* Unhandled signal */
		cp = "Interrupt by unhandled signal";
		break;
	case FAIL_FILE_ERROR:			/* File I/O error */
		cp = "File I/O error";
		break;
	case FAIL_SOCKET_ERROR:			/* Socket I/O error */
		cp = "Socket I/O error";
		break;
	case FAIL_HANGUP:			/* Client hung up on us */
		cp = "Process stopped";
		break;
	case FAIL_LOST_CLIENT:			/* Timeout waiting for client */
		cp = "Timeout waiting for command from client";
		break;
	case FAIL_OUT_OF_MEMORY:		/* Failed malloc() */
		cp = "Out of memory!";
		break;
	case FAIL_PROGERR:			/* Fatal program error */
		cp = "Fatal program error!";
		break;
	case FAIL_PIPE:				/* Rec'd SIGPIPE - DTS 28Jul96*/
		cp = "Received pipe failure signal!";
		break;
	case FAIL_CONFUSION:			/* Shouldn't happen */
	default:
		cp = "Complete confusion!";
		break;
	}
	if (err != FAIL_SOCKET_ERROR) {
		fprintf(stdout, "-ERR POP3 Server Abnormal Shutdown: %s\r\n",cp);
		fflush(stdout);
	}

	fprintf(stderr,"[%d] -ERR POP3 Server Abnormal Shutdown:\n%s\n",mypid,cp);
	if ( debug ) {
		fprintf(logfp,"[%d] -ERR POP3 Server Abnormal Shutdown:\n%s\n",mypid,cp);
		fclose(logfp);
	}
	mem_free();
	close(0);
	close(1);
	exit(err);				/* Exit with error */
}

/**************************************************************************/

#ifdef STANDALONE

/* Routine "main" in here to define a standalone main server.
 *	File:  server.c
 *	Author: Derric Scott (dtscott@scott.net)
 *	Copyright (c) 1998 Derric Scott (dtscott@scott.net)
 *		All rights reserved
 *	Created: 24Mar98
 *
 *	This program is a prefix to the in.pop3d daemon that will enable
 *	it to be used as a standalone daemon without being run from inetd.
 *
 */

#include	<process.h>
#include	<sys/wait.h>

char *naddr2str(struct sockaddr_in *saptr);
void err_quit(const char *);
void err_sys(const char *);
void svrsetsigs();

static	int	port = TCP_SERV_PORT;
static	int	inet = 1;

int 
main(int argc, char *argv[])
{   
	char str[MAXSTR];
	struct sockaddr_in serv, child;
	int	listenfd, sockfd, os2_sockfd;
	int  childlen, on = 1;
	int	pidstatus;
	pid_t pid;
	struct linger linger;
	char *child_argv[] = {NULL, NULL, NULL, NULL, NULL};
	unsigned long handle;
	int i = 0;

	parse_opts(argc,argv);

	if( inet ) 		/* if it should run via inetd, then just go... */
		inetd_main(argc, argv);

	child_argv[i++] = argv[0];
	if( debug )
		child_argv[i++] = "-d";
	if( use_syslog )
		child_argv[i++] = "-s";

	svrsetsigs();

	if( use_syslog )
		openlog( argv[0], LOG_PID, LOG_MAIL );
	xsyslog(LOG_MAIL|LOG_INFO, "POP3 daemon starting");

	if ((listenfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		snprintf(str,MAXSTR, "socket error: %s", strerror(errno));
		err_quit(str);
	}

	/* Try to set timeouts down for quick turn-arounds... */
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));
	linger.l_onoff = on;
	linger.l_linger = 15;
	setsockopt(listenfd, SOL_SOCKET, SO_LINGER, (void *)&linger, sizeof(linger));

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = htonl(INADDR_ANY);
	serv.sin_port = htons(port);
   
	if (bind(listenfd, (struct sockaddr *) &serv, sizeof(serv)) < 0) {
		snprintf(str, MAXSTR, "bind error: %s", strerror(errno));
		err_quit(str);
	}
   
	if (listen(listenfd, SOMAXCONN) < 0) {
		snprintf(str, MAXSTR, "listen error: %s", strerror(errno));
		err_quit(str);
	}

	if( (handle = sem_create(argv[0])) == 0 )
		fail(FAIL_PROGERR);

	for (;;)  {	/* Main processing loop */
		memset(&child, 0, sizeof(child));
		childlen = sizeof(child);
		if ((sockfd = accept(listenfd, (struct sockaddr *) &child, &childlen)) < 0) {
			if (errno != EINTR && errno != EINVAL) {
				snprintf(str, MAXSTR, "accept error (%s): %s",
				naddr2str(&child), strerror(errno));
				err_sys(str);
			}
        		continue;
		}

		if ( (os2_sockfd = _getsockhandle(sockfd)) < 0 ) {
			snprintf(str, MAXSTR, "socket error: %s", strerror(errno));
			err_quit(str);
		}
		_itoa(os2_sockfd, str, 10);
		child_argv[i] = str;

		sem_reset(handle);
		if ( (pid = spawnvp(P_NOWAIT, argv[0], child_argv)) < 0 ) {
			snprintf(str, MAXSTR, "spawn error: %s", strerror(errno));
			err_sys(str);
		}

	/* Now a quick while loop to clear all exited processes */
		while (waitpid( -1, &pidstatus, WNOHANG ) > 0 ) ;
		sem_wait(handle);	/* wait for child starting */
		close (sockfd);

	} /* end for(;;) */
}

void
err_sys(const char *msg) {
	fputs(msg, stderr);
	putc('\n', stderr);
	xsyslog(LOG_MAIL|LOG_INFO, msg );
}

void
err_quit(const char *msg) {
	err_sys(msg);
	exit(1);
}

char *
naddr2str(struct sockaddr_in *saptr) {
	static char str[MAXSTR];
	char	*bp, *ap;
	int	l;
	struct sockaddr sa;
	
        /* check for null/zero family */
        if (saptr == NULL)
                return "NULLADDR";
        if (saptr->sin_family == 0)
                return "0";

        if (saptr->sin_family == AF_INET)
                return inet_ntoa(saptr->sin_addr);

        /* unknown family -- just dump bytes */
	memcpy(&sa, saptr, sizeof(sa));
        snprintf(str, MAXSTR, "Family %d: ", sa.sa_family);
        bp = &str[strlen(str)];
        ap = sa.sa_data;
        for (l = sizeof sa.sa_data; --l >= 0; ) {
                sprintf(bp, "%02x:", *ap++ & 0377);
                bp += 3;
        }
        *--bp = '\0';
        return str;

} /* end naddr2str */

static void d_catchint(int sig);
static void d_hangup(int sig);
static void d_sigchld(int sig);

void
svrsetsigs()
{
	int	i;

	for( i = 0; i < NSIG; i++) {
		/* default is to just log and continue */
		signal(i,d_catchint);
	}
	/* and now let the following override certain ones... */

	/* Handle process signals ourself */
	signal(SIGCHLD, d_sigchld);		/* A subprocess has exited */
	signal(SIGHUP,  d_hangup);		/* socket signals */
	signal(SIGTERM, d_hangup);
	signal(SIGINT,  d_hangup);
	signal(SIGQUIT, d_hangup);
	signal(SIGSEGV, d_hangup);
	signal(SIGILL,  d_hangup);
	signal(SIGPIPE, d_hangup);
}

static void
d_catchint(int sig) {
	char msg[MAXSTR];
	sprintf(msg, "ERROR - Caught unexpected signal: %d", sig);
	err_sys(msg);
	signal(sig, d_catchint);		/* Reset to get it again. */
}
	
static void
d_hangup(int sig) {
	char msg[MAXSTR];
	sprintf(msg, "Caught signal %d - Hanging up.", sig);
	err_sys(msg);
	exit(0);
}

static void
d_sigchld(int sig) {
	int pidstatus;
	while (waitpid( -1, &pidstatus, WNOHANG ) > 0 ) ;
	signal(SIGCHLD, d_sigchld);	/* Reset to get it again. */
}

#endif

/**************************************************************************/


int
parse_opts(int argc, char *argv[]) 
{
	extern char *optarg;
	int fd = 0;
	int opt;
#ifdef STANDALONE
	int got_b=0, got_i=0;
#endif

	if(isdigit((unsigned char)*argv[argc-1])) {	/* Socket number from inetd */
		argc--;
		fd = atoi(argv[argc]);
	}
	while ((opt = getopt(argc, argv, "p:dsibh")) != EOF) {
		switch(opt) {
		  case 'd':
			debug = 1;
			break;
		  case 's':
			use_syslog = 1;
			break;
#ifdef STANDALONE
		  case 'b':
			inet = 0;
			got_b = 1;
			break;
		  case 'i':
			inet = 1;
			got_i = 1;
			break;
		  case 'p':
			port = atoi(optarg);
			break;
#endif
		  case 'h':
		  default:
			fprintf(stderr,"Usage: %s [options]\n",argv[0]);
			fprintf(stderr,"  -h       Help - this message\n");
			fprintf(stderr,"  -d       Debug logging mode\n");
			fprintf(stderr,"  -s       Enable logging to syslog\n");
#ifdef STANDALONE
			fprintf(stderr,"  -i       Inetd mode (default)\n");
			fprintf(stderr,"  -b       Background daemon mode\n");
			fprintf(stderr,"  -p port  Listening port number\n");
#endif
			exit(1);
		} /* end switch */
	} /* end while */

#ifdef STANDALONE
	if( got_b && got_i ) {
		fprintf(stderr,"Options b and i are mutually exclusive.\n");
		fprintf(stderr,"  Use '-h' for help.\n");
		exit(1);
	}
#endif
	return fd;
} /* end parse_opts */
