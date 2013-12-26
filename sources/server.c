#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include "pop3.h"

#define SYSLOGSERREQ	xsyslog( SYSLOGPRI, "Servicing %s @ %s",user_name,client_ip)

extern FILE	*logfp;
extern int	mypid;
extern int	debug;
extern int	pass_delay;

extern char *svr_hostname;
extern char *client_ip;
extern char *user_name;
extern char *user_mailbox;
extern char *svr_buf;

const char *svr_invalid = "-ERR Invalid command; valid commands:";

/**************************************************************************/

/* Server Authentification State; process client USER/APOP command */
int
svr_auth(int state, char *inbuf)
{
	char *command, *arg;

	command = strtok(inbuf, " ");
	if (strcmp(command, "quit") == 0)
		return(svr_shutdown());
	/* Expecting USER or APOP command */
	if (strcmp(command, "user") == 0) {
		arg = strtok(NULL, " @");
		if( arg ) {
			strncpy(user_name, arg, CLI_BUFSIZ);
			strcpy(svr_buf, "+OK please send PASS command\r\n");
			state = SVR_PASS_STATE;
		}
		else 
			strcpy(svr_buf, "-ERR user name required\r\n");
 	} else if (strcmp(command, "apop") == 0) {
		pass_delay = 0;
		arg = strtok(NULL, " ");
		if( arg )
			strncpy(user_name, arg, CLI_BUFSIZ);
		arg = strtok(NULL, " ");
 		if (verify_user_apop(user_name, arg) == -1) {
 			sprintf(svr_buf, "-ERR invalid usercode or hashcode from %s\r\n",
				client_ip);
			pass_delay = 1;
 			/* DTS added 14Feb96 for syslogging */
 			xsyslog( SYSLOGPRI,
 				"Invalid user or password for \"%s\" from %s",
					user_name, client_ip);
 			return(SVR_AUTH_STATE);
 		}
#ifdef VIRTUAL
		if(virtual_mode) {
			xsyslog( SYSLOGPRI,
				"Virtual svr_hostname, servicing request for %s from %s",
				user_name, client_ip);
			snprintf(svr_buf, SVR_BUFSIZ, "%s%s", virt_spooldir, user_name);
		} else {
			SYSLOGSERREQ;
			snprintf(svr_buf, SVR_BUFSIZ, "%s%s", DEF_MAIL_DIR, user_name);
		}
#else
		SYSLOGSERREQ;

#endif
 		return(fld_fromsp());
 	} else {
 		sprintf(svr_buf,"%s  USER, APOP, QUIT\r\n",svr_invalid);
	}
 		
	return(state);
}

/* Server Password State; process client PASS command */
int
svr_pass(int state, char *inbuf)
{
	char *command, *arg;

	command = strtok(inbuf, " ");

	if (strcmp(command, "quit") == 0)
		return(svr_shutdown());
	/* Expecting PASS command */
	if (strcmp(command, "pass") != 0) {
		sprintf(svr_buf, "%s  PASS,  QUIT\r\n", svr_invalid);
		return(state);
	}
	arg = strtok(NULL, " ");
	pass_delay = 0;
	/* Verify usercode/password pair */
	switch( verify_user(user_name, arg) ) {
	    case -1:
		sprintf(svr_buf, "-ERR invalid usercode or password from %s\r\n",
			client_ip);
		/* DTS added 14Feb96 for syslogging */
		xsyslog( SYSLOGPRI,
			"Invalid user or password for \"%s\" from %s", user_name, client_ip);
		pass_delay = 1;
		return(SVR_AUTH_STATE);
	    case -2:
		strcpy(svr_buf, "-ERR undefined mailbox. Call for assistance.\r\n");
		xsyslog( SYSLOGPRI,
			"Undefined mailbox for user %s", user_name);
		pass_delay = 1;
		return(SVR_AUTH_STATE);
	    default:
		break;
	}
		
	/* DTS added 14Feb96 for syslogging */
#ifdef VIRTUAL
	if(virtual_mode) {
		xsyslog( SYSLOGPRI,
			"Virtual svr_hostname, servicing request for %s from %s",
			user_name, client_ip);
		snprintf(svr_buf, SVR_BUFSIZ, "%s%s", virt_spooldir, user_name);
	} else {
		SYSLOGSERREQ;
		snprintf(svr_buf, SVR_BUFSIZ, "%s%s", DEF_MAIL_DIR, user_name);
	}
#else
	SYSLOGSERREQ;
#endif
	return(fld_fromsp());
}

/* Server Transaction State; process client mailbox command */
int
svr_trans(int state, char *inbuf)
{
	enum { quit, stat, list, uidl, retr, dele, top, rset, last, noop };
	const char *cmd_names[] = { "quit", "stat", "list", "uidl", "retr", 
				"dele", "top", "rset", "last", "noop" };
	const int size = sizeof(cmd_names)/sizeof(char *);
	const char *num_required = "-ERR message number required (e.g. %s)\r\n";
	int msgnum, num;
	char *command, *arg;

	command = strtok(inbuf, " ");
	arg = strtok(NULL, " ");
	if ( arg )
		msgnum = atoi(arg);
	else
		msgnum = -1;

	/* Expecting mailbox command */
	for(num = 0; num < size && strcmp(command, cmd_names[num]); num++);

	switch( num ) {
		case quit:	return(svr_shutdown());
		case stat:	fld_stat(); break;
		case list:	fld_list(msgnum); break;
		case uidl:	fld_uidl(msgnum); break;
		case retr:
			if ( arg ) fld_retr(msgnum, -1);
			else	   sprintf(svr_buf, num_required, "RETR 1");
			break;
		case dele:
			if ( arg ) fld_delete(msgnum);
			else	   sprintf(svr_buf, num_required, "DELE 1");
			break;
		case top:
			if ( arg ) {
				arg = strtok(NULL, " ");
				if ( arg ) fld_retr(msgnum, atoi(arg));
				else	   fld_retr(msgnum, 10);
			}
			else	sprintf(svr_buf, num_required, "TOP 1 7");
			break;
		case rset:	fld_reset(); break;
		case last:	fld_last(); break;
		case noop:	strcpy(svr_buf, "+OK\r\n"); break;
		default:
			sprintf(svr_buf,
			"%s  DELE, LAST, LIST, NOOP, RETR, RSET, STAT, TOP, UIDL  or  QUIT\r\n",
			svr_invalid);
	}

	return(state);
}

/* Server Folder State; need to open another folder */
int
svr_fold(int state, char *inbuf)
{
	char *command;

	command = strtok(inbuf, " ");
	if (strcmp(command, "quit") == 0) {
		return(svr_shutdown());
	} else if (strcmp(command, "noop") == 0) {
		strcpy(svr_buf, "+OK\r\n");
	} else {
		sprintf(svr_buf, "%s  NOOP  or  QUIT\r\n", svr_invalid);
	}
	return(state);
}

/* Prepare to shutdown POP3 server */
int
svr_shutdown()
{
	fld_release();
	snprintf(svr_buf, SVR_BUFSIZ, "+OK %s POP3 Server (Version %s) shutdown.\r\n",
		svr_hostname, VERSION);
	return(SVR_DONE_STATE);
}

void
svr_abort(int err_code)
{
	fld_release();
	fail(err_code);
}

/**************************************/

void
svr_data_in(char *buf)
{
/* Wait for command from client */
	alarm(SVR_TIMEOUT_CLI);
	if (fgetl(buf, CLI_BUFSIZ, stdin) == NULL) {
		xsyslog( SYSLOGPRI, "svr_data_in: input error %d", errno);
		if ( debug )
			fprintf(logfp, "[%d] svr_data_in: input error: %d\n", mypid, errno);
		svr_abort(FAIL_SOCKET_ERROR);
	}
	alarm(0);
}

void
svr_data_out(char *buf)
{
	/* Send out response to client */
	alarm(SVR_TIMEOUT_SEND);
	fputs(buf, stdout);
	if( ferror(stdout)) {
		xsyslog( SYSLOGPRI, "svr_data_out: output error %d", errno);
		if ( debug )
			fprintf(logfp, "[%d] svr_data_out: output error: %d\n", mypid, errno);
		svr_abort(FAIL_SOCKET_ERROR);
	}
	fflush(stdout);
	alarm(0);
}

