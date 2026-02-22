#include "ft_ping.h"

int no_ac(const char *program_name)
{
    printf("%s: missing host operand\n", program_name);
    printf("Try '%s --help' or '%s --usage' for usage information.\n", program_name, program_name);
    return RETURN_CODE_NO_AC;
}

int help(const char *program_name)
{
    printf("Usage: %s [OPTION...] HOST ...\n", program_name);
    printf("Send ICMP ECHO_REQUEST packets to network hosts.\n");
    printf("\n");
    printf(" Options valid for all request types:\n");
    printf("  -v, --verbose              verbose output\n");
    printf("\n");
    printf("  -?, --help                 give this help list\n");
    printf("      --usage                give a short usage message\n");
    printf("\n");
    printf("Mandatory or optional arguments to long options are also mandatory or optional\n");
    printf("for any corresponding short options.\n");
    printf("\n");
    printf("Options marked with (root only) are available only to superuser.\n");
    printf("\n");
    printf("Report bugs to <bug-inetutils@gnu.org>.\n");
    return 0;
}