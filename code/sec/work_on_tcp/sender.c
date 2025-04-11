#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/time.h>

#define DEST_PORT 8888
#define SRC_PORT 8888
#define PACKET_SIZE 65535

volatile sig_atomic_t stop = 0;
void handle_sigint(int sig) {
    stop = 1;
}

struct pseudo_header {
    u_int32_t src_addr;
    u_int32_t dst_addr;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_len;
};

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    for (; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

long get_usec() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000L + tv.tv_usec;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file_to_send> [--delay=0.5] [--repeat=1] [--logfile=sent.csv]\n", argv[0]);
        return 1;
    }

    double delay_seconds = 0.5;
    int repeat = 1;
    char logfile_name[128] = "sent_log.csv";

    for (int i = 2; i < argc; ++i) {
        if (strncmp(argv[i], "--delay=", 8) == 0)
            delay_seconds = atof(argv[i] + 8);
        else if (strncmp(argv[i], "--repeat=", 9) == 0)
            repeat = atoi(argv[i] + 9);
        else if (strncmp(argv[i], "--logfile=", 10) == 0)
            strncpy(logfile_name, argv[i] + 10, sizeof(logfile_name)-1);
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror("fopen"); return 1; }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    char *message = malloc(fsize + 1);
    if (!message) { perror("malloc"); fclose(fp); return 1; }

    fread(message, 1, fsize, fp);
    fclose(fp);
    message[fsize++] = 0x04; // EOF

    const char *dest_ip = getenv("INSECURENET_HOST_IP");
    const char *src_ip = getenv("SECURENET_HOST_IP");

    if (!dest_ip || !src_ip) {
        fprintf(stderr, "ENV INSECURENET_HOST_IP or SECURENET_HOST_IP not set\n");
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) { perror("socket"); return 1; }

    int one = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DEST_PORT),
        .sin_addr.s_addr = inet_addr(dest_ip)
    };

    FILE *logfile = fopen(logfile_name, "w");
    if (!logfile) { perror("fopen logfile"); return 1; }
    fprintf(logfile, "run,index,ascii,time_us\n");

    char buffer[PACKET_SIZE], pseudogram[PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *) buffer;
    struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof(struct iphdr));
    struct pseudo_header psh;

    for (int r = 1; r <= repeat; r++) {
        printf("\n[=== RUN %d ===]\n", r);
        long start_usec = get_usec();

        for (size_t i = 0; i < fsize && !stop; i++) {
            memset(buffer, 0, PACKET_SIZE);

            iph->ihl = 5;
            iph->version = 4;
            iph->tos = 0;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            iph->id = htons(rand() % 65535);
            iph->frag_off = 0;
            iph->ttl = 64;
            iph->protocol = IPPROTO_TCP;
            iph->saddr = inet_addr(src_ip);
            iph->daddr = inet_addr(dest_ip);
            iph->check = 0;
            iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

            tcph->source = htons(SRC_PORT);
            tcph->dest = htons(DEST_PORT);
            tcph->seq = htonl(2000 + i);
            tcph->ack_seq = 0;
            tcph->doff = 5;
            tcph->syn = 0;
            tcph->ack = 1;
            tcph->window = htons((unsigned char)message[i]);
            tcph->check = 0;
            tcph->urg_ptr = 0;

            psh.src_addr = iph->saddr;
            psh.dst_addr = iph->daddr;
            psh.placeholder = 0;
            psh.protocol = IPPROTO_TCP;
            psh.tcp_len = htons(sizeof(struct tcphdr));

            memcpy(pseudogram, &psh, sizeof(psh));
            memcpy(pseudogram + sizeof(psh), tcph, sizeof(struct tcphdr));
            tcph->check = checksum((unsigned short *)pseudogram, sizeof(psh) + sizeof(struct tcphdr));

            sendto(sockfd, buffer, ntohs(iph->tot_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

            long usec = get_usec();
            fprintf(logfile, "%d,%zu,%d,%ld\n", r, i, (unsigned char)message[i], usec);
            printf("[>] Sent byte '%c' (%d)\n", message[i], (unsigned char)message[i]);

            double rand_uniform = (double)rand() / (RAND_MAX + 1.0);
            double exp_delay = -log(1.0 - rand_uniform) * delay_seconds;  // Exponential with mean = delay_seconds
            usleep((useconds_t)(exp_delay * 1e6));
        }

        long end_usec = get_usec();
        double duration = (end_usec - start_usec) / 1000000.0;
        double throughput = fsize / duration;

        printf("[✔] Run %d complete: %.2f seconds, %.2f bytes/sec\n", r, duration, throughput);
    }

    fclose(logfile);
    close(sockfd);
    free(message);
    printf("[✔] Transmission complete.\n");
    return 0;
}
