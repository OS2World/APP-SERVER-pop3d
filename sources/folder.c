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
 *	folder.c
 *
 *	REVISIONS:
 *		02-27-90 [ks]	original implementation
 *	1.000	03-04-90 [ks]
 *	1.001	06-24-90 [ks]	allow TRANS state if 0 msgs in folder
 *				implement optional TOP command
 *	1.002	07-22-91 [ks]	reset index counter after folder rewind
 *				in fld_release (Thanks to John Briggs,
 *				vaxs09@vitro.com, Vitro Corporation,
 *				Silver Spring, MD for finding this bug!)
 *	1.004	11-13-91 [ks]	leave original mailbox intact during POP
 *				session (Thanks to Dave Cooley,
 *				dwcooley@colby.edu for suggesting this)
 *	1.005	01-04-96 [dts]	change mktemp to mkstemp to avoid security
 *				hole with mktemp (timing attack).
 *
 *	1.010	05-31-99 [avl]	First port for OS/2 + EMX.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include "pop3.h"

#ifdef VIRTUAL
extern int virtual_mode;
extern char *virt_spooldir;
extern char *virt_workdir;
#endif

/* In main.c */
extern char *svr_hostname;
extern char *svr_buf;
extern char *user_name;
extern char *user_mailbox;
extern void svr_data_out(char *buf);

const char *svr_nomsg = "-ERR no messages in mailbox\r\n";
static char *pop_hdr = NULL;		/* Header */

static struct fld_item *fld_msg = NULL;	/* Struct for mailbox stats */
static int fld_max = -1;		/* Actual # msgs in mailbox */
static int fld_highest = -1;		/* Max msg accessed by client */
static int uidl_ready = 0;		/* UIDL made for all msgs */
static unsigned long lock_handle = 0;	/* Lock semaphore handle */

static int fld_select(char *mbox);
static void retr_fromsp(int msgnum, int linecnt);
static int msg_fromsp(char *mbox);

/**************************************************************************/

/* Open a FromSpace delimited mailbox */
int
fld_fromsp()
{
	int cnt;
	char tmp_buf[SVR_BUFSIZ];

	/* Release previously opened mailbox */
	if (fld_msg != NULL)
		fld_release();

	/* Construct header for new user */
	snprintf(tmp_buf, SVR_BUFSIZ,  "%s %s@%s\r\n",POP3_RCPT_HDR,
			user_name, svr_hostname);
	pop_hdr = xstrdup(tmp_buf);

	/* Check the user mailbox */
	if ((cnt = fld_select(user_mailbox)) < 0) {
		if (cnt == -2)
			sprintf(svr_buf,
			"-ERR mailbox directory %s is locked now\r\n", user_mailbox);
		else
			sprintf(svr_buf,
			"-ERR cannot find mailbox directory %s\r\n", user_mailbox);
		return(SVR_FOLD_STATE);
	} else {
		sprintf(svr_buf, "+OK %d messages ready for %s in %s\r\n",
			cnt, user_name, user_mailbox);
		return(SVR_TRANS_STATE);
	}
}

/**************************************************************************/

/* Mark a message for deletion */
void
fld_delete(int msgnum)
{
	int i = msgnum - 1;

	if (fld_max <= 0) {
		strcpy(svr_buf, svr_nomsg);
		return;
	}

	if (i < 0 || i >= fld_max) {
		sprintf(svr_buf, "-ERR invalid message; number out of range\r\n");
	} else {
		fld_msg[i].status |= MSG_DELETED;
		sprintf(svr_buf, "+OK message %d marked for deletion\r\n",
			msgnum);
		if (i > fld_highest)
			fld_highest = i;
	}
}

/* Report the highest access number for this mailbox */
void
fld_last()
{
	sprintf(svr_buf, "+OK %d\r\n", (fld_highest+1));
}

/* Give information about messages in mailbox folder */
void
fld_list(int msgnum)
{
	int i;

	if (fld_max <= 0) {
		strcpy(svr_buf, svr_nomsg);
		return;
	}

	if (msgnum == -1) {
		sprintf(svr_buf, "+OK %d messages; msg# and size (in octets) for undeleted messages:\r\n", 
				fld_max);
		svr_data_out(svr_buf);
		for (i=0; i<fld_max; ++i) {
			if (fld_msg[i].status == 0) {
				sprintf(svr_buf,"%d %ld\r\n",
					(i+1), fld_msg[i].bcount);
				svr_data_out(svr_buf);
			}
		}
		sprintf(svr_buf,".\r\n");
	} else {
		i = msgnum - 1;
		if (i < 0 || i >= fld_max)
			sprintf(svr_buf, "-ERR invalid message; number out of range\r\n");
		else if (fld_msg[i].status & MSG_DELETED)
			sprintf(svr_buf, "-ERR message %d has been marked for deletion\r\n",
				msgnum);
		else if (fld_msg[i].status & MSG_UNAVAILABLE)
			sprintf(svr_buf, "-ERR message %d unavailable\r\n",
				msgnum);
		else
			sprintf(svr_buf, "+OK %d %ld\r\n",
				msgnum, fld_msg[i].bcount);
	}
}

/* Give id listing of messages in mailbox folder */
void
fld_uidl(int msgnum)
{
	int i;
	FILE *msg_fp;

	if (fld_max <= 0) {
		strcpy(svr_buf, svr_nomsg);
		return;
	}

	if (msgnum == -1 && !uidl_ready) {
		for (i=0; i<fld_max; ++i) {
			if( fld_msg[i].id != NULL ) continue;
			if ((msg_fp = fopen(fld_msg[i].file_name, "rb")) == NULL) {
				fld_msg[i].status |= MSG_UNAVAILABLE;
				continue;
			}
			do_md5_file(msg_fp, 0, fld_msg[i].count, svr_buf);
			fclose(msg_fp);
			fld_msg[i].id = xstrdup(svr_buf);
		}
		uidl_ready = 1;
	}
	i = msgnum - 1;
	if (i >= 0 && i < fld_max && fld_msg[i].id == NULL) {
		if ((msg_fp = fopen(fld_msg[i].file_name, "rb")) == NULL) 
			fld_msg[i].status |= MSG_UNAVAILABLE;
		else {
			do_md5_file(msg_fp, 0, fld_msg[i].count, svr_buf);
			fclose(msg_fp);
			fld_msg[i].id = xstrdup(svr_buf);
		}
	}

	if (msgnum == -1) {
		sprintf(svr_buf, "+OK %d messages; msg# and id for undeleted messages:\r\n",
				fld_max);
		svr_data_out(svr_buf);
		for (i=0; i<fld_max; ++i) {
			if (fld_msg[i].status == 0) {
				sprintf(svr_buf, "%d %s\r\n",
					(i+1), fld_msg[i].id);
				svr_data_out(svr_buf);
			}
		}
		sprintf(svr_buf, ".\r\n");
	} else {
		i = msgnum - 1;
		if ((i < 0 || i >= fld_max))
			sprintf(svr_buf, "-ERR invalid message; number out of range\r\n");
		else if (fld_msg[i].status & MSG_DELETED)
			sprintf(svr_buf, "-ERR message %d has been marked for deletion\r\n",
				msgnum);
		else if (fld_msg[i].status & MSG_UNAVAILABLE)
			sprintf(svr_buf, "-ERR message %d unavailable\r\n",
				msgnum);
		else {
			sprintf(svr_buf, "+OK %d %s\r\n",
				msgnum, fld_msg[i].id);
		}
	}
}

/* Reset deleted messages and highest access number */
void
fld_reset()
{
	int i;

	if (fld_max <= 0) {
		strcpy(svr_buf, svr_nomsg);
		return;
	}
	/* Reset messages marked for deletion */
	for (i=0; i<fld_max; ++i) {
		fld_msg[i].status &= ~MSG_DELETED;
	}
	/* Reset highest access number for this mailbox */
	fld_highest = -1;
	sprintf(svr_buf, "+OK %d messages ready for %s in %s\r\n",
		fld_max, user_name, user_mailbox);
}

/* Retrieve a message from mailbox */
void
fld_retr(int msgnum, int linecnt)
{
	int i = msgnum - 1; 
	if (fld_max <= 0) {
		strcpy(svr_buf, svr_nomsg);
		return;
	}

	if (i < 0 || i >= fld_max) {
		sprintf(svr_buf, "-ERR invalid message; number out of range\r\n");
	} else if (fld_msg[i].status & MSG_DELETED) {
		sprintf(svr_buf, "-ERR message %d has been marked for deletion\r\n",
			msgnum);
	} else if (fld_msg[i].status & MSG_UNAVAILABLE) {
		sprintf(svr_buf, "-ERR message %d unavailable\r\n",
			msgnum);
	} else {
		sprintf(svr_buf, "+OK message %d (%ld octets):\r\n",
			msgnum, fld_msg[i].bcount);
		svr_data_out(svr_buf);
		retr_fromsp(msgnum, linecnt);
		sprintf(svr_buf, ".\r\n");
		if ( linecnt != -1 && i > fld_highest)
			fld_highest = i;
	}
}

/* Give message count and total size (in octets) of a mailbox folder */
void
fld_stat()
{
	int i;
	long total_cnt = 0L;

	if (fld_max <= 0) {
		strcpy(svr_buf, "+OK 0 0\r\n");
		return;
	}
	for (i=0; i<fld_max; ++i) {
		total_cnt += fld_msg[i].bcount;
	}
	sprintf(svr_buf, "+OK %d %ld\r\n", fld_max, total_cnt);
}

/**************************************************************************/

/* Attempt to load a mailbox folder */
static int
fld_select(char *mbox)
{
	struct stat stat_buf;

	/* Reset folder variables */
	fld_highest = -1;

	if (stat(mbox,&stat_buf) < 0) 
		return -1;

	if (!S_ISDIR(stat_buf.st_mode))
		return -1;

	if((lock_handle = sem_create( mbox )) == 0)
		return -2;

	fld_max = msg_fromsp(mbox);

	return(fld_max);
}

/* Close a mailbox folder; remove messages marked for deletion */
void
fld_release()
{
	int i;

	for (i=0; i<fld_max; ++i) {
		if ((fld_msg[i].status & MSG_DELETED) != 0)
			unlink(fld_msg[i].file_name);
		xfree(fld_msg[i].file_name);
		xfree(fld_msg[i].id);
	}

	xfree(fld_msg);
	sem_close(lock_handle);

	fld_highest = -1;
	fld_max = -1;
	uidl_ready = 0;

}

/********************************************/

/* Send a FromSP delimited message to the POP3 client */
static void
retr_fromsp(int msgnum, int linecnt)
{
	char *cp, *tp;
	int msgbody = 0;
	FILE *msg_fp;

	if ((msg_fp = fopen(fld_msg[msgnum-1].file_name, "rb")) == NULL) {
		fld_msg[msgnum-1].status |= MSG_UNAVAILABLE;
		return;
	}

	/* Setup for byte-stuff on lines that start with '.' */
	cp = svr_buf;
	*cp = DOT_CHAR;
	++cp;
	/* Display message for the client */
	if (pop_hdr != NULL)
		svr_data_out(pop_hdr);
	while ((tp = fgetl(cp, SVR_BUFSIZ-2, msg_fp)) != NULL) {
		/* Use CR-LF line terminator */
		tp--;
		if (*(tp-1) != CR_CHAR)
			strcpy(tp,"\r\n");
		/* Byte-stuff lines that start with '.' */
		if (*cp == DOT_CHAR)
			svr_data_out(svr_buf);
		else
			svr_data_out(cp);
		if ((msgbody) && (--linecnt == 0)) {
			break;
		} else {
			if (*cp == CR_CHAR) {
				msgbody = 1;
				if (linecnt == 0)
					break;
			}
		}
	}
	fclose(msg_fp);
}

/**************************************************************************/

/* Load messages from a mailbox delimited by FromSPACE */
static int
msg_fromsp(char *mbox)
{
	int i, k;
	int header_len;
	char **file_names, **name;
	struct stat stat_buf;
	struct fld_item *mp;
	char tmp_buf[MAXSTR];

	strcpy(tmp_buf, mbox);
	strcat(tmp_buf, "/*");
	file_names = _fnexplode(tmp_buf);	/* Take the list of files */
	if( file_names == NULL )		/* Empty directory */
		return 0;

	for( i=0; file_names[i] != NULL; i++ );
	if (i == 0) {				/* Probably, never happen */
		_fnexplodefree(file_names);
		return 0;
	}

	/* Get an array for storing info about messages in folder */
	fld_msg = (t_fld_item *)xmalloc(sizeof(t_fld_item) * i);

	header_len = strlen(pop_hdr);
	for( name=file_names, i=0; *name != NULL; name++ ) {
		if (stat(*name, &stat_buf) < 0)
			continue;
		if (stat_buf.st_size == 0)
			continue;

		for(k=i; k>0; k--) {		/* Sorting by mtime */
			if(fld_msg[k-1].mtime < stat_buf.st_mtime) break;
			fld_msg[k] = fld_msg[k-1];
		}
		mp = fld_msg + k;
		mp->mtime = stat_buf.st_mtime;
		mp->status = 0;
		mp->file_name = xstrdup(*name);
		mp->count = stat_buf.st_size;
		mp->bcount = header_len + stat_buf.st_size;
		mp->id = NULL;
		i++;
	}
	_fnexplodefree(file_names);
	return i;
}

/************************************************/

