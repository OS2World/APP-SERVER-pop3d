#ifdef MD5_CRYPT

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "md5/md5.h"

typedef struct md5_ctx MD5_CTX;

#define MAX_STRING_LEN 256

char * md5_crypt(char *passwd, char *user)
{
    MD5_CTX context;
    static unsigned char digest[17];
    char string[MAX_STRING_LEN];
    unsigned int i;
    static unsigned char itoa64[] =         /* 0 ... 63 => ASCII - 64 */
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    sprintf(string, "%s:%s", user, passwd);

    md5_init_ctx(&context);
    md5_process_bytes((unsigned char *) string, strlen(string), &context);
    md5_finish_ctx(&context, digest);

    for (i = 0; i < 16; i++)
	digest[i] = itoa64[digest[i]&0x3f];
    digest[16] = '\0';
    return digest;
}

#endif