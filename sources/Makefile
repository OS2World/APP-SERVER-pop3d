# make file for the IP/TCP/POP3 server for OS/2


# Set the executable names.  
POP3D = pop3d.exe
ADMIN = admin.exe
MAILRCV = mailrcv.exe

# -DTACACS_AUTH for that form of authentication.
# -DVIRTUAL	for VIRTUAL hosting (new, not functional yet).
# -DSTANDALONE	for standalone, non-inetd server
# -DMD5_CRYPT	for simple password encryption method

CC	= gcc
CFLAGS	= -O3 -mpentium -I. -Wall -Zomf  -DSTANDALONE #-DMD5_CRYPT

.SUFFIXES: .c .obj
.c.obj:
	$(CC) $(CFLAGS) -c $<

OBJS  = server.obj main.obj folder.obj util.obj md5.obj user.obj \
	md5_crypt.obj tacacs_auth.obj virtual.obj md5/md5.obj syslog.obj

LIBS  = -L. -lsocket -lcrypt -Zcrtdll -Zomf -s
#MD5 = md5/md5.obj

all: $(POP3D) $(MAILRCV) $(ADMIN)

$(POP3D): $(OBJS)
	$(CC) -o $(POP3D) $(OBJS) $(LIBS)
$(MAILRCV): mailrcv.c
	$(CC) -o $(MAILRCV) $(CFLAGS) mailrcv.c $(LIBS)
$(ADMIN): admin.obj md5_crypt.obj $(MD5)
	$(CC) -o $(ADMIN) admin.obj md5_crypt.obj $(LIBS) $(MD5)

server.obj: server.c
main.obj:	main.c pop3.h
folder.obj: folder.c pop3.h
util.obj: util.c pop3.h
md5.obj: md5.c md5/md5.h pop3.h
user.obj: user.c pop3.h
syslog.obj: syslog.c syslog.h
md5_crypt.obj: md5_crypt.c md5/md5.h
tacacs_auth.obj: tacacs_auth.c tacacs.h
virtual.obj: virtual.c pop3.h
admin.obj:	admin.c

md5/md5.obj: md5/md5.c md5/md5.h
	$(CC) $(CFLAGS) -c md5/md5.c -o md5/md5.obj
