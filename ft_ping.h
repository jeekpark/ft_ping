#ifndef FT_PING_H
# define FT_PING_H

#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define RETURN_CODE_NO_AC 0b1000000

int no_ac(const char *program_name);
int help(const char *program_name);
#endif