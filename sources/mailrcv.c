/* Mail delivering program for OS/2 sendmail.
 * Alexey Leko, 1999.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <io.h>
#include <sys/stat.h>

#define EX_OK           0       /* successful termination */

#define EX__BASE        64      /* base value for error messages */

#define EX_USAGE        64      /* command line usage error */
#define EX_DATAERR      65      /* data format error */
#define EX_NOINPUT      66      /* cannot open input */
#define EX_NOUSER       67      /* addressee unknown */
#define EX_NOHOST       68      /* host name unknown */
#define EX_UNAVAILABLE  69      /* service unavailable */
#define EX_SOFTWARE     70      /* internal software error */
#define EX_OSERR        71      /* system error (e.g., can't fork) */
#define EX_OSFILE       72      /* critical OS file missing */
#define EX_CANTCREAT    73      /* can't create (user) output file */
#define EX_IOERR        74      /* input/output error */
#define EX_TEMPFAIL     75      /* temp failure; user is invited to retry */
#define EX_PROTOCOL     76      /* remote error in protocol */
#define EX_NOPERM       77      /* permission denied */
#define EX_CONFIG       78      /* configuration error */


#define MAXSTR 256

void usage(void);
int find_user(char* user, char *file_name);
void save_message(FILE* input);
int  create_name();

static int user_unknown = 1;
static char msg_file[MAXSTR];

int main( int argc, char* argv[] )
{
	if(argc < 3) usage();

	if( !find_user(argv[2], argv[1]) ) {
		fprintf(stderr, "Mailbox for user %s isn't found.\n", argv[2]);
		return EX_NOUSER;
	}
	save_message(stdin);
	if(user_unknown)
		return EX_NOUSER;
	return EX_OK;
}

int find_user(char* user, char *file_name)
{
	FILE *cfg_file;
	struct stat stat_buf;
	char buff[MAXSTR];
	char *name, *mb;

	strcpy(msg_file, file_name);
	mb = msg_file + strlen(msg_file) - 1;
	if( *mb == '\\' || *mb == '/' )	{	/* Directory name */
		strcpy(++mb, user);
		if (stat(msg_file, &stat_buf) == 0 &&
			S_ISDIR(stat_buf.st_mode) ) {
			user_unknown = 0;
			return 1;
		}

		strcpy(mb, "unknown");
		if (stat(msg_file, &stat_buf) == 0 &&
			S_ISDIR(stat_buf.st_mode) )
			return 1;
		return 0;
	}

	*msg_file = 0;
	cfg_file = fopen(file_name, "r");	/* File name */
	if (!cfg_file) {
		fprintf(stderr, "File %s not found\n", file_name);
		exit(EX_OSFILE);
	}

	while(fgets(buff, MAXSTR, cfg_file)) {
		if(*buff == '#' || *buff == '\n') continue;

		name = strtok(buff, " \t\n");
		if( (mb = strtok(NULL, " \t\n")) == NULL)
			continue;

		if( stricmp(name, user) == 0 ) {
			strncpy(msg_file, mb, MAXSTR);
			user_unknown = 0;
			break;
		}
		if( stricmp(name, "unknown") == 0 )
			strncpy(msg_file, mb, MAXSTR);
	}
	fclose(cfg_file);
	return (*msg_file != 0);
}

void save_message(FILE* input)
{
	int i;
	FILE* output;

	if( !create_name() ) {
		fprintf(stderr, "Unable to create the name for message file.\n");
		exit(EX_TEMPFAIL);
	}
	output=fopen(msg_file, "w");
	if( !output ) {
		fprintf(stderr, "Unable to open the message file.\n");
		exit(EX_CANTCREAT);
	}

	while( (i = getc(input)) != EOF ) {
		if(putc(i, output) == EOF) {
			fprintf(stderr, "Error writing to file %s.\n", msg_file);
			exit(EX_IOERR);
		} 
	}
}

int create_name()
{
	char* first_let;
	struct stat stat_buf;

	if (stat(msg_file, &stat_buf) < 0 ||
			!S_ISDIR(stat_buf.st_mode) ) {
		fprintf(stderr, "Directory %s does not exist.\n", msg_file);
		exit(EX_CONFIG);
	}

	first_let = msg_file + strlen(msg_file);
	*first_let++ = '\\';

	_itoa(time(0), first_let, 16);
	strcat(msg_file, ".msg");

	for( *first_let = 'a'; *first_let <= 'z'; (*first_let)++ )
		if( access(msg_file, 0) != 0 )
			return 1;

	return 0;
}

void usage()
{
	fputs("Usage: mailrcv path user_name\n", stderr);
	fputs("path is the name of MAILBOX directory or MAILADDR file.\n", stderr);
	exit(EX_USAGE);
}

