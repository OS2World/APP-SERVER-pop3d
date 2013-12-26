#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

#include "pop3.h"

#ifdef MD5_CRYPT
char *md5_crypt(char *pass, char *user);
#else
char *crypt(char *pass, char *salt);
#endif

extern char *timestamp;
extern char *user_mailbox;

/**************************************************************************/

int mailbox_name(char *user)
{
	char *mb = getenv("MAILBOX");

	if (mb == NULL)
		return 0;

	user_mailbox = (char *) xmalloc( strlen(mb)+strlen(user)+2 );
	strcpy(user_mailbox, mb);
	strcat(user_mailbox, "/");
	strcat(user_mailbox, user);
	
	for (mb=user_mailbox; *mb; mb++)
		if(*mb == '\\') *mb = '/';
	return 1;
}

int find_user(char* user, char* user_info, char *file_name )
{
	FILE *cfg_file;
	int user_len=strlen(user);
	unsigned char c;
	int success = 0;

	cfg_file = fopen(file_name, "r");
	if (!cfg_file)
		return 0;

	strlwr(user);
	while(fgets(user_info, MAXSTR, cfg_file)) {
		if(*user_info == '#' || *user_info == LF_CHAR) continue;

		c = user_info[user_len];
		if( (isspace(c) || c ==':') &&
				strnicmp(user_info, user, user_len) == 0 ) {
			success = 1;
			break;
		}
	}
	fclose(cfg_file);
	return success;
}


int
passwd_verify_user(char *user, char *pass)
{
	char name[MAXSTR];
	char buff[MAXSTR];
	char *mb = 0, *passwd = 0;
	char *fname = 0;
	int  secure;

	if( user ==NULL || pass == NULL )
		return -1;

	if( (secure = mailbox_name(user)) == 0 )	/* MAILADDR cfg file*/
		snprintf(name, MAXSTR, "%s%s", getenv("ETC"), MAILADDR_FILE);
	else {
		fname = getenv("PASSWORDS");
		if( !fname )
			snprintf(name, MAXSTR, "%s%s", getenv("ETC"), POP3D_PASSWORD_FILE);
	}
	if( !fname )
		fname = name;

	if( !find_user(user, buff, fname) )
		return -1;

	if(secure) {
		strtok(buff, ":");
		passwd = strtok(NULL, ": \t\n");
		if(passwd == NULL)
			return -1;
#ifdef MD5_CRYPT
		if( strcmp(passwd, md5_crypt(pass, user)) == 0 ) return 1;
#else
		if( strcmp(passwd, crypt(pass, passwd)) == 0 ) return 1;
#endif
	} else {
		strtok(buff, " \t\n");
		mb = strtok(NULL, " \t\n");
		passwd = strtok(NULL, " \t\n");

		if(passwd == NULL)
			return -1;
		if(mb == NULL) 
			return -2;
		user_mailbox = xstrdup(mb);
		for (mb=user_mailbox; *mb; mb++)
			if(*mb == '\\') *mb = '/';

		if( strcmp(passwd, pass) == 0 ) return 1;
	}

	return -1;
} /* end passwd_verify_user */

/* Verify a usercode/password */
int
verify_user(user,pass)
char *user;
char *pass;
{
#ifdef TACACS_AUTH
	return( tacacs_verify_user(user,pass) );
#else
	return( passwd_verify_user(user,pass) );
#endif
}

/**************************************************************************/

/* Verify a usercode/password-hash */
int
verify_user_apop(char *user, char *pass)
{
	char name[MAXSTR];
	char buff[MAXSTR];
	char *passwd;
	char *end = timestamp + strlen(timestamp);

	if( user ==NULL || pass == NULL )
		return -1;

	if( mailbox_name(user) == 0 )		/* Can't find mailbox dirctory*/
		return -1;

	snprintf(name, MAXSTR, "%s%s", getenv("ETC"), APOP_PASSWORD_FILE);

	if( !find_user(user, buff, name) )
		return -1;

	strtok(buff, ":");
	passwd = strtok(NULL, ": \t\n");
	if(passwd == NULL)
		return -1;

	strcpy(end, passwd);
	do_md5_string(timestamp, strlen(timestamp), buff);
	*end = 0;

	if (strcmp(pass, buff) != 0)
		return -1;

	return 0;
}

/**************************************************************************/

