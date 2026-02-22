#include "ft_ping.h"

#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <float.h>
#include <sys/select.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define PING_PAYLOAD_SIZE 56
#define PING_INTERVAL_NS 1000000000LL

static volatile sig_atomic_t g_stop = 0;

typedef struct s_options
{
    bool verbose;
    const char *host;
}   t_options;

typedef struct s_stats
{
    uint64_t transmitted;
    uint64_t received;
    double rtt_min_ms;
    double rtt_max_ms;
    double rtt_sum_ms;
}   t_stats;

static void on_sigint(int signo)
{
    (void)signo;
    g_stop = 1;
}

static uint16_t internet_checksum(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;

    while (len > 1)
    {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len == 1)
        sum += (uint16_t)(p[0] << 8);

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)~sum;
}

static long long timespec_to_ns(struct timespec ts)
{
    return (long long)ts.tv_sec * 1000000000LL + (long long)ts.tv_nsec;
}

static struct timespec ns_to_timespec(long long ns)
{
    struct timespec ts;
    ts.tv_sec = ns / 1000000000LL;
    ts.tv_nsec = ns % 1000000000LL;
    if (ts.tv_nsec < 0)
    {
        ts.tv_nsec += 1000000000LL;
        ts.tv_sec -= 1;
    }
    return ts;
}

static double ns_to_ms(long long ns)
{
    return (double)ns / 1000000.0;
}

static int resolve_ipv4(
    const char *program_name,
    const char *host,
    struct sockaddr_in *out,
    char *ipstr,
    size_t ipstr_sz
)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;

    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0)
    {
        fprintf(stderr, "%s: %s: %s\n", program_name, host, gai_strerror(rc));
        return -1;
    }

    memcpy(out, res->ai_addr, sizeof(struct sockaddr_in));
    if (inet_ntop(AF_INET, &out->sin_addr, ipstr, ipstr_sz) == NULL)
    {
        fprintf(stderr, "%s: inet_ntop: %s\n", program_name, strerror(errno));
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return 0;
}

static int parse_args(int argc, const char **argv, t_options *out)
{
    out->verbose = false;
    out->host = NULL;

    const char *program_name = argv[0];
    if (argc == 1)
        return no_ac(program_name);

    for (int i = 1; i < argc; i++)
    {
        const char *arg = argv[i];
        if (strcmp(arg, "-?") == 0 || strcmp(arg, "--help") == 0 || strcmp(arg, "--usage") == 0)
        {
            (void)help(program_name);
            return 1;
        }
        if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0)
        {
            out->verbose = true;
            continue;
        }
        if (arg[0] == '-')
        {
            fprintf(stderr, "%s: invalid option -- '%s'\n", program_name, arg);
            fprintf(stderr, "Try '%s --help' or '%s --usage' for usage information.\n", program_name, program_name);
            return 2;
        }
        if (out->host != NULL)
        {
            fprintf(stderr, "%s: extra operand '%s'\n", program_name, arg);
            fprintf(stderr, "Try '%s --help' or '%s --usage' for usage information.\n", program_name, program_name);
            return 2;
        }
        out->host = arg;
    }

    if (out->host == NULL)
        return no_ac(program_name);
    return 0;
}

static int decode_icmp_error(char *buf, size_t buf_sz, uint8_t type, uint8_t code)
{
    if (buf_sz == 0)
        return -1;
    buf[0] = '\0';

    if (type == ICMP_DEST_UNREACH)
    {
        const char *msg = "Destination Unreachable";
        if (code == ICMP_NET_UNREACH) msg = "Destination Net Unreachable";
        else if (code == ICMP_HOST_UNREACH) msg = "Destination Host Unreachable";
        else if (code == ICMP_PROT_UNREACH) msg = "Destination Protocol Unreachable";
        else if (code == ICMP_PORT_UNREACH) msg = "Destination Port Unreachable";
        else if (code == ICMP_FRAG_NEEDED) msg = "Frag needed and DF set";
        else if (code == ICMP_SR_FAILED) msg = "Source Route Failed";
        snprintf(buf, buf_sz, "%s", msg);
        return 0;
    }
    if (type == ICMP_TIME_EXCEEDED)
    {
        const char *msg = "Time to live exceeded";
        if (code == ICMP_EXC_FRAGTIME) msg = "Fragment reassembly time exceeded";
        snprintf(buf, buf_sz, "%s", msg);
        return 0;
    }
    snprintf(buf, buf_sz, "ICMP type %u code %u", (unsigned)type, (unsigned)code);
    return 0;
}

static bool extract_inner_seq_id(
    const uint8_t *icmp_payload,
    size_t icmp_payload_len,
    uint16_t *out_id,
    uint16_t *out_seq
)
{
    if (icmp_payload_len < sizeof(struct iphdr))
        return false;

    const struct iphdr *inner_ip = (const struct iphdr *)icmp_payload;
    size_t inner_iphdr_len = (size_t)inner_ip->ihl * 4;
    if (inner_ip->ihl < 5 || inner_iphdr_len > icmp_payload_len)
        return false;
    if (icmp_payload_len < inner_iphdr_len + sizeof(struct icmphdr))
        return false;

    const struct icmphdr *inner_icmp = (const struct icmphdr *)(icmp_payload + inner_iphdr_len);
    if (inner_icmp->type != ICMP_ECHO)
        return false;

    *out_id = ntohs(inner_icmp->un.echo.id);
    *out_seq = ntohs(inner_icmp->un.echo.sequence);
    return true;
}

static bool handle_incoming_packet(
    const t_options *opt,
    const uint16_t ident,
    const uint16_t expected_seq,
    const uint8_t *buf,
    ssize_t nread,
    t_stats *stats
)
{
    if (nread < (ssize_t)sizeof(struct iphdr))
        return false;

    const struct iphdr *ip = (const struct iphdr *)buf;
    size_t iphdr_len = (size_t)ip->ihl * 4;
    if (ip->ihl < 5 || (ssize_t)iphdr_len > nread)
        return false;
    if (nread < (ssize_t)(iphdr_len + sizeof(struct icmphdr)))
        return false;

    const struct icmphdr *icmp = (const struct icmphdr *)(buf + iphdr_len);
    size_t icmp_len = (size_t)nread - iphdr_len;
    const uint8_t *icmp_payload = (const uint8_t *)icmp + sizeof(*icmp);
    size_t icmp_payload_len = icmp_len - sizeof(*icmp);

    char src_ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip)) == NULL)
        snprintf(src_ip, sizeof(src_ip), "?");

    if (icmp->type == ICMP_ECHOREPLY)
    {
        uint16_t rid = ntohs(icmp->un.echo.id);
        uint16_t rseq = ntohs(icmp->un.echo.sequence);
        if (rid != ident || rseq != expected_seq)
            return false;

        struct timespec sent_ts;
        if (icmp_payload_len < sizeof(sent_ts))
            return false;
        memcpy(&sent_ts, icmp_payload, sizeof(sent_ts));

        struct timespec now_ts;
        clock_gettime(CLOCK_MONOTONIC, &now_ts);
        long long rtt_ns = timespec_to_ns(now_ts) - timespec_to_ns(sent_ts);
        double rtt_ms = ns_to_ms(rtt_ns);

        stats->received++;
        if (rtt_ms < stats->rtt_min_ms) stats->rtt_min_ms = rtt_ms;
        if (rtt_ms > stats->rtt_max_ms) stats->rtt_max_ms = rtt_ms;
        stats->rtt_sum_ms += rtt_ms;

        printf("%zu bytes from %s: icmp_seq=%u ttl=%u time=%.3f ms\n",
            icmp_len, src_ip, (unsigned)rseq, (unsigned)ip->ttl, rtt_ms);
        fflush(stdout);
        return true;
    }

    if (icmp->type == ICMP_DEST_UNREACH || icmp->type == ICMP_TIME_EXCEEDED)
    {
        uint16_t inner_id = 0;
        uint16_t inner_seq = 0;
        if (!extract_inner_seq_id(icmp_payload, icmp_payload_len, &inner_id, &inner_seq))
            return false;
        if (inner_id != ident || inner_seq != expected_seq)
            return false;

        if (opt->verbose)
        {
            char msg[128];
            decode_icmp_error(msg, sizeof(msg), icmp->type, icmp->code);
            printf("From %s: icmp_seq=%u %s\n", src_ip, (unsigned)inner_seq, msg);
            fflush(stdout);
        }
        return true;
    }

    return false;
}

static int send_echo_request(
    int sock,
    const struct sockaddr_in *dst,
    uint16_t ident,
    uint16_t seq,
    struct timespec *out_sent_ts
)
{
    uint8_t packet[sizeof(struct icmphdr) + PING_PAYLOAD_SIZE];
    struct icmphdr icmp;

    clock_gettime(CLOCK_MONOTONIC, out_sent_ts);

    memset(&icmp, 0, sizeof(icmp));
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.id = htons(ident);
    icmp.un.echo.sequence = htons(seq);

    memset(packet, 0, sizeof(packet));
    memcpy(packet, &icmp, sizeof(icmp));
    memcpy(packet + sizeof(icmp), out_sent_ts, sizeof(*out_sent_ts));
    for (size_t i = sizeof(*out_sent_ts); i < PING_PAYLOAD_SIZE; i++)
        packet[sizeof(icmp) + i] = (uint8_t)('0' + (i % 10));

    ((struct icmphdr *)packet)->checksum = 0;
    ((struct icmphdr *)packet)->checksum = htons(internet_checksum(packet, sizeof(packet)));

    ssize_t sent = sendto(sock, packet, sizeof(packet), 0, (const struct sockaddr *)dst, sizeof(*dst));
    return (sent == (ssize_t)sizeof(packet)) ? 0 : -1;
}

static void print_stats(
    const char *host,
    const t_stats *stats,
    struct timespec start_ts,
    struct timespec end_ts
)
{
    long long elapsed_ns = timespec_to_ns(end_ts) - timespec_to_ns(start_ts);
    double elapsed_ms = ns_to_ms(elapsed_ns);

    printf("\n--- %s ping statistics ---\n", host);
    double loss = 0.0;
    if (stats->transmitted > 0)
        loss = (double)(stats->transmitted - stats->received) * 100.0 / (double)stats->transmitted;
    printf("%llu packets transmitted, %llu received, %.0f%% packet loss, time %.0fms\n",
        (unsigned long long)stats->transmitted,
        (unsigned long long)stats->received,
        loss,
        elapsed_ms);

    if (stats->received > 0)
    {
        double avg = stats->rtt_sum_ms / (double)stats->received;
        printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n", stats->rtt_min_ms, avg, stats->rtt_max_ms);
    }
}

int main(int argc, const char **argv)
{
    const char *program_name = argv[0];
    t_options opt;
    int rc = parse_args(argc, argv, &opt);
    if (rc == 1)
        return 0;
    if (rc != 0)
        return rc;

    struct sockaddr_in dst;
    char dst_ip[INET_ADDRSTRLEN];
    if (resolve_ipv4(program_name, opt.host, &dst, dst_ip, sizeof(dst_ip)) != 0)
        return 2;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0)
    {
        fprintf(stderr, "%s: socket: %s\n", program_name, strerror(errno));
        return 2;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    printf("PING %s (%s): %d data bytes\n", opt.host, dst_ip, PING_PAYLOAD_SIZE);
    fflush(stdout);

    const uint16_t ident = (uint16_t)(getpid() & 0xFFFF);
    uint16_t seq = 0;

    t_stats stats;
    memset(&stats, 0, sizeof(stats));
    stats.rtt_min_ms = DBL_MAX;

    struct timespec start_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);

    while (!g_stop)
    {
        seq++;
        struct timespec sent_ts;
        if (send_echo_request(sock, &dst, ident, seq, &sent_ts) == 0)
            stats.transmitted++;

        long long sent_ns = timespec_to_ns(sent_ts);
        long long deadline_ns = sent_ns + PING_INTERVAL_NS;

        bool done = false;
        while (!g_stop && !done)
        {
            struct timespec now_ts;
            clock_gettime(CLOCK_MONOTONIC, &now_ts);
            long long remain_ns = deadline_ns - timespec_to_ns(now_ts);
            if (remain_ns <= 0)
                break;

            struct timeval tv;
            tv.tv_sec = (time_t)(remain_ns / 1000000000LL);
            tv.tv_usec = (suseconds_t)((remain_ns % 1000000000LL) / 1000LL);

            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sock, &rfds);

            int ready = select(sock + 1, &rfds, NULL, NULL, &tv);
            if (ready == 0)
                break;
            if (ready < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }

            uint8_t rbuf[2048];
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            ssize_t nread = recvfrom(sock, rbuf, sizeof(rbuf), 0, (struct sockaddr *)&from, &fromlen);
            if (nread <= 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }
            done = handle_incoming_packet(&opt, ident, seq, rbuf, nread, &stats);
        }

        if (g_stop)
            break;

        struct timespec after_ts;
        clock_gettime(CLOCK_MONOTONIC, &after_ts);
        long long sleep_ns = deadline_ns - timespec_to_ns(after_ts);
        if (sleep_ns > 0)
        {
            struct timespec req = ns_to_timespec(sleep_ns);
            while (nanosleep(&req, &req) != 0 && errno == EINTR && !g_stop)
                ;
        }
    }

    struct timespec end_ts;
    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    print_stats(opt.host, &stats, start_ts, end_ts);

    close(sock);
    return 0;
}
