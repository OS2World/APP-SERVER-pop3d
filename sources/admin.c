/* admin.c: simple program for manipulating password file under OS/2.
 * Derived from Apache htpasswd.c.
 * Alexey Leko, 1999.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <pwd.h>
#include <sys/types.h>
#include <share.h>
#include <errno.h>

extern void __sleep2();

#define MAXSTR 256
#define USER_LEN 32

#ifdef MD5_CRYPT
#define PASSWD_LEN 16
char *md5_crypt(char *pass, char *user);
#else
#define PASSWD_LEN 13
char *crypt(char *pass, char *salt);
#endif

char *get_password(char *user)
{
    static char passwd[_PASSWORD_LEN+1];
    strcpy(passwd, getpass("New password: "));
    if (strlen(passwd) == 0) {
	_itoa(time(0), passwd, 16);
#ifdef MD5_CRYPT
	strcpy(passwd, md5_crypt(passwd, user));
#else
	strcpy(passwd, crypt(passwd, user));
#endif
	passwd[8] = 0;
	fprintf(stderr, "Generated password: %s\n", passwd);
    } else {
	if (strcmp(passwd, (char *) getpass("Re-type new password:"))) {
	    fputs("They don't match, sorry.\n", stderr);
	    exit(1);
	}
    }
    return passwd;
}

static void usage(void)
{
    fputs("Usage: admin [-c] [passwordfile] username\n", stderr);
    fputs("The -c flag creates a new file.\n", stderr);
    fputs("The passwordfile can be omitted if the PASSWORDS\n", stderr);
    fputs("environment variable is defined.\n", stderr);
    exit(1);
}

int main(int argc, char *argv[])
{
    FILE *passwd_file = NULL;
    char buff[MAXSTR];
    char str[MAXSTR];
    char info[MAXSTR];
    char *name, *user, *passwd = 0;
    char *u, *p;
    char mode[] = "r+";
    int  found = 0, newfile = 0; 
    int  i = 32;

    name = getenv("PASSWORDS");
    if(argc > 1 && strcmp(argv[1], "-c") == 0) {
	mode[0] = 'w';
	newfile = 1;
    }

    user = argv[--argc];
    if(argc == newfile)
	usage();
    if(argc-1 == newfile) {
	if(!name) usage();
    } else
	name = argv[--argc];
    if(argc-1 != newfile) 
	usage();

    if(strlen(user) > USER_LEN) {
	fputs("The name is too long.\n", stderr);
	exit(1);
    }

    passwd = get_password(user);
#ifdef MD5_CRYPT
    sprintf(info, "%s:%s", user, md5_crypt(passwd, user));
#else
    _itoa(time(0)&0xFF, buff, 16);
    sprintf(info, "%s:%s", user, crypt(passwd, buff));
#endif

    while(i--) {
	if( (passwd_file = _fsopen(name, mode, SH_DENYWR)) != NULL )
	    break;
	if(errno == EACCES) {
	    __sleep2(100);
	    continue;
	}
	break;
    }
    if (passwd_file == NULL) {
	fprintf(stderr,
		"Could not open passwords file %s for writing:\n%s.\n", name, strerror(errno));
	exit(1);
    }

    while (fgets(buff, MAXSTR, passwd_file)) {
	if(*buff == '#' || *buff == '\n') 
		continue;
	strcpy(str, buff);
	u = strtok(str, ":");
	if (stricmp(user, u)) 
	    continue;
	p = strtok(NULL, ": \t\n");
	fseek(passwd_file, -(strlen(buff)+1), SEEK_CUR);
	if(strlen(p) != PASSWD_LEN) {		/* Record is destroyed */
	    *buff = '#';
	    fputs(buff, passwd_file);
	    fseek(passwd_file, -(strlen(buff)+1), SEEK_CUR);
	    continue;
	}
	printf("Changing password for user %s\n", user);
	fputs(info, passwd_file);
	found = 1;
	break;
    }
    if (!found) {
	printf("Adding user %s\n", user);
	fputs(info, passwd_file);
	putc('\n', passwd_file);
    }
    fclose(passwd_file);
    return 0;
}
