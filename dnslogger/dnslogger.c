#include "config.h"
#include "omg_dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <sys/time.h>

#define BUFSIZE 2048

#define NUM_LABELS 512
struct labels {
    uint8_t*         data;
    size_t           label_idx;
    omg_dns_label_t* label;
};

#define NUM_RRS 128
struct rrs {
    size_t         rr_idx;
    omg_dns_rr_t*  rr;
    int*           ret;
    size_t*        label_idx;
    struct labels* labels;
};


static int label_callback(const omg_dns_label_t* label, void* context)
{
    struct labels* labels = (struct labels*)context;

    if (labels->label_idx == NUM_LABELS)
        return OMG_DNS_ENOMEM;

    labels->label[labels->label_idx] = *label;
    labels->label_idx++;

    return OMG_DNS_OK;
}

static int rr_callback(int ret, const omg_dns_rr_t* rr, void* context)
{
    struct rrs* rrs = (struct rrs*)context;

    if (rrs->rr_idx == NUM_RRS)
        return OMG_DNS_ENOMEM;

    rrs->ret[rrs->rr_idx] = ret;
    if (rr)
        rrs->rr[rrs->rr_idx] = *rr;
    rrs->rr_idx++;
    if (rrs->rr_idx != NUM_RRS)
        rrs->label_idx[rrs->rr_idx] = rrs->labels->label_idx;

    return OMG_DNS_OK;
}

static void parse(uint8_t* data, size_t len)
{
    omg_dns_t     dns = OMG_DNS_T_INIT;
    struct rrs    rrs    = { 0, 0, 0 };
    struct labels labels = { 0, 0, 0 };
    size_t        n;

    rrs.rr        = calloc(NUM_RRS, sizeof(omg_dns_rr_t));
    rrs.ret       = calloc(NUM_RRS, sizeof(int));
    rrs.label_idx = calloc(NUM_RRS, sizeof(size_t));
    rrs.labels    = &labels;

    labels.data  = data;
    labels.label = calloc(NUM_LABELS, sizeof(omg_dns_label_t));

    omg_dns_set_rr_callback(&dns, rr_callback, (void*)&rrs);
    omg_dns_set_label_callback(&dns, label_callback, (void*)&labels);
    omg_dns_parse(&dns, data, len);


    for (n = 0; n < rrs.rr_idx; n++) {
        omg_dns_rr_t* rr = &(rrs.rr[n]);
        if (!omg_dns_rr_is_question(rr)) continue;
        if (!omg_dns_rr_labels(rr)) continue;

        if (n != 0) printf(",");
        printf("\"");

        size_t l    = rrs.label_idx[n];
        size_t loop = 0;

        while (!omg_dns_label_is_end(&(labels.label[l]))) {
            if (!omg_dns_label_is_complete(&(labels.label[l]))) {
                printf(" <incomplete>");
                break;
            }

            if (loop > labels.label_idx) {
                printf(" <loop detected>");
                break;
            }
            loop++;

            if (omg_dns_label_have_offset(&(labels.label[l]))) {
                size_t l2;

                for (l2 = 0; l2 < labels.label_idx; l2++) {
                    if (omg_dns_label_have_dn(&(labels.label[l2]))
                            && omg_dns_label_offset(&(labels.label[l2])) == omg_dns_label_offset(&(labels.label[l]))) {
                        l = l2;
                        break;
                    }
                }
                if (l2 < labels.label_idx) {
                    printf(" <offset>");
                    continue;
                }
                printf(" <offset missing>");
                break;
            } else if (omg_dns_label_have_extension_bits(&(labels.label[l]))) {
                printf(" <extension>");
                break;
            } else if (omg_dns_label_have_dn(&(labels.label[l]))) {
                uint8_t* dn    = data + omg_dns_label_dn_offset(&(labels.label[l]));
                size_t   dnlen = omg_dns_label_length(&(labels.label[l]));

                while (dnlen--) {
                    printf("%c", *dn++);
                }
                printf(".");
                l++;
            } else {
                printf("<invalid>");
                break;
            }
        }
        printf("\"");
    }


    free(rrs.rr);
    free(rrs.ret);
    free(rrs.label_idx);
    free(labels.label);
}

void error(const char *msg) {
    perror(msg);
    exit(0);
}

char *progname;
void usage(int rc) {
    fprintf(rc == 0 ? stdout : stderr,
            "Usage: %s [-b SO_RCVBUF] LISTEN_HOST LISTEN_PORT\n\
\n\
\n\
", progname);
    exit(rc);
}

long long timestamp_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec*1000LL + tv.tv_usec/1000;
}

int main(int argc, char *argv[]) {
    int opt;
    int rcvbuf = 0;
    struct sockaddr_in sock_addr;
    int sock_fd;

    progname = basename(argv[0]);
    while ((opt = getopt(argc, argv, "hb:q:")) != -1) {
        switch (opt) {
            case 'b':
                rcvbuf = atoi(optarg);
                break;
            case 'h':
                usage(0);
            default: /* '?' */
                usage(-1);
        }
    }

    if (argc - optind != 2) {
        usage(-1);
    }

    char *listen_host = argv[optind];
    char *listen_port = argv[optind+1];

    sock_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = inet_addr(listen_host);
    sock_addr.sin_port = htons(atoi(listen_port));
    if (bind(sock_fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) == -1)
        error("bind()");

    if (rcvbuf > 0) {
        if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
            error("setsockopt()");
    }

    struct sockaddr_in sa;
    size_t sa_size = sizeof(sa);

    uint8_t buf[BUFSIZE];
    size_t payload_bytes;

	while (1) {
        payload_bytes = recvfrom(sock_fd, buf, BUFSIZE, 0,
                (struct sockaddr *)&sa, (socklen_t*)&sa_size);

        if (payload_bytes == 0)  continue;
        if (payload_bytes < 0)   break;

        printf("[%lld, \"%s\", %u, %ld, ", timestamp_ms(), inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), payload_bytes);
        parse(buf, payload_bytes);
        printf("]\n");

        // Set flags to respond with "No such name"
        buf[2] = 0x81;
        buf[3] = 0x83;

        sendto(sock_fd, buf, payload_bytes, 0,
                (struct sockaddr *)&sa, sa_size);
    }

}
