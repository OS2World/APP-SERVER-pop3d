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
 *      Modified by 
 *	Fabio Coatti
 *	cova@felix.unife.it
 *	Now verify_user() can verify no-shadow passwd file even
 * 	if compiled with -DSHADOWPWD
 *
 **************************************
 *
 *	util.c
 *
 *	REVISIONS:
 *		02-27-90 [ks]	original implementation
 *	1.000	03-04-90 [ks]
 *      1.001   29-04-97 [cova]
 *
 *	1.010	05-31-99 [avl]	First port for OS/2 + EMX.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>
#include <syslog.h>

#include "pop3.h"

extern FILE *logfp;
extern int mypid;
extern int debug;
extern int use_syslog;

/**************************************************************************/

inline void *xmalloc(size_t size) {
	void *res = malloc(size);
	if (res == NULL)
		fail(FAIL_OUT_OF_MEMORY);
	return res;
}

inline void *xstrdup(char *string) {
	char *res = strdup(string);
	if (res == NULL)
		fail(FAIL_OUT_OF_MEMORY);
	return res;
}

void xsyslog(int pri, const char *fmt, ...)
{
	va_list ap;

	if ( !use_syslog ) return;

	va_start(ap,fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

/**************************************************************************/

char *
apop_timestamp()
{
	time_t t;
	struct tm *tm;
	char buff[MAXSTR];
	int len;

	time(&t);
	tm = localtime(&t);
	len = strftime(buff, MAXSTR, "<%a %b %d %H:%M:%S %Y ", tm);
	snprintf(buff+len, MAXSTR-len, "%d>", getpid());

	return xstrdup(buff);
}

/**************************************************************************/

/* Read a line of text from a stream. If more than n-1  */
/* characters are read without a line terminator (LF),  */
/* discard characters until line terminator is located. */
char *
fgetl(char *buf, int n, FILE *fp)
{
	int ch;
	int i = 0;
	char *cp = buf;

	n -= 2;
	while( (ch = getc(fp)) != LF_CHAR ) {
		if(ch == EOF) return NULL;
		if(i++ < n) *cp++ = ch;
	}
	*cp++ = LF_CHAR;
	*cp = NULL_CHAR;

	return cp;	/* returns pointer to terminating 0 */
}

/* Prepare client command for server */
void
cmd_prepare(char *buf)
{
	unsigned char *cp = buf, *last = NULL;

	if (buf == NULL)
		return;
	/* Convert command verb to lowercase */
	while (*cp != NULL_CHAR && !isspace(*cp)) {
		*cp = tolower(*cp);
		++cp;
	}
	/* Strip trailing whitespace from client command */
	for (cp=buf; *cp != NULL_CHAR; cp++)
		if(!isspace(*cp)) last = cp;
	if( last != NULL)
		*(++last) = NULL_CHAR;
	else
		*buf = NULL_CHAR;
}

/**************************************************************************/

char *
get_fqdn()
{
	static char fqdn[256] = "";
	char buff[100];
	struct hostent *h;

	if (fqdn[0] != '\0')
		return fqdn;

	if (gethostname(buff, sizeof(buff)) != 0)
	{
		perror("get_fqdn");
		return NULL;
	}

	h = gethostbyname(buff);
	if (!h)
	{
		fprintf(stderr, "get_fqdn: gethostbyname() failed\n");
		return NULL;
	}

	strcpy(fqdn, h->h_name);
	return fqdn;
}

/**************************************************************************/

#define INCL_DOS
#define INCL_ERRORS
#include <os2.h>

char* sem_name(char *name)
{
	char *sem, *cp;
	sem = (char *)xmalloc(strlen(name)+8);
	strcpy(sem, "\\SEM32\\");
	strcat(sem, name);
	for(cp=sem; *cp; cp++) 
		if(*cp == '/' || *cp == ':') *cp = '\\';
	return sem;
}

unsigned long sem_create(char *name)
{
	unsigned long handler;
	int rc;
	char *sem;

	sem = sem_name(name);
	rc = DosCreateEventSem(sem, &handler, 0L, 0L);
	xfree(sem);
	if( rc == NO_ERROR )				/* Success */
		return handler;
	return 0;
}

void sem_post(char *name)
{
	unsigned long handler = 0;
	int rc;
	char *sem;

	sem = sem_name(name);
	rc = DosOpenEventSem(sem, &handler);
	xfree(sem);
	if( rc != NO_ERROR )				
		return;
	rc = DosPostEventSem(handler);
	return;
}

void sem_reset(unsigned long handler)
{
	unsigned long count;
	if (handler)
		DosResetEventSem( handler, &count );
}

void sem_wait(unsigned long handler)
{
	if (handler)
		DosWaitEventSem( handler, 5000L );
}

void sem_close(unsigned long handler)
{
	if (handler)
		DosCloseEventSem( handler );
}

