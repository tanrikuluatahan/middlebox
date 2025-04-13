#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <math.h>

#define PORT 8888
#define BUFFER_SIZE 65536
#define MAX_FILE_SIZE 100000

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    for (; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

struct pseudo_header {
    u_int32_t src_addr;
    u_int32_t dst_addr;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_len;
};

int main(int argc, char *argv[]) {
    char logfile_name[128] = "recv_log.csv";

    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "--logfile=", 10) == 0) {
            strncpy(logfile_name, argv[i] + 10, sizeof(logfile_name) - 1);
        }
    }

    int sockfd;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    char covert_buffer[MAX_FILE_SIZE];
    size_t covert_len = 0;
    int file_index = 1;
    int run_number = 1;

    unsigned int last_seq = 0;
    int out_of_order = 0;
    unsigned int missing = 0;
    int eof = 0;
    long last_usec = 0;
    double sum_ia = 0, sum_sq_ia = 0;
    int count_ia = 0;

    char *host_ip = getenv("INSECURENET_HOST_IP");
    if (!host_ip) {
        fprintf(stderr, "INSECURENET_HOST_IP not set\n");
        exit(1);
    }

    FILE *logfile = fopen(logfile_name, "w");
    if (!logfile) {
        perror("fopen logfile");
        return 1;
    }
    fprintf(logfile, "run,index,ascii,time_us\n");

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    printf("Listening for TCP packets on %s:%d...\n", host_ip, PORT);

    while (1) {
        ssize_t len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                               (struct sockaddr *)&client_addr, &addr_len);
        if (len < 0) {
            perror("recvfrom");
            continue;
        }

        struct iphdr *iph = (struct iphdr *)buffer;
        if (iph->protocol != IPPROTO_TCP) continue;

        int ip_len = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr *)(buffer + ip_len);
        if (ntohs(tcph->dest) != PORT) continue;

        char *src_ip_str = inet_ntoa(*(struct in_addr *)&iph->saddr);
        int src_port = ntohs(tcph->source);

        if (tcph->syn && !tcph->ack) {
            printf("[+] Received SYN from %s:%d\n", src_ip_str, src_port);

            char sendbuf[BUFFER_SIZE];
            memset(sendbuf, 0, BUFFER_SIZE);
            struct iphdr *iph_reply = (struct iphdr *)sendbuf;
            struct tcphdr *tcph_reply = (struct tcphdr *)(sendbuf + sizeof(struct iphdr));

            iph_reply->ihl = 5; iph_reply->version = 4; iph_reply->tos = 0;
            iph_reply->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            iph_reply->id = htons(rand() % 65535);
            iph_reply->frag_off = 0; iph_reply->ttl = 64; iph_reply->protocol = IPPROTO_TCP;
            iph_reply->saddr = iph->daddr;
            iph_reply->daddr = iph->saddr;
            iph_reply->check = 0;
            iph_reply->check = checksum((unsigned short *)iph_reply, sizeof(struct iphdr));

            tcph_reply->source = tcph->dest;
            tcph_reply->dest = tcph->source;
            tcph_reply->seq = htonl(1000);
            tcph_reply->ack_seq = htonl(ntohl(tcph->seq) + 1);
            tcph_reply->doff = 5;
            tcph_reply->syn = 1; tcph_reply->ack = 1;
            tcph_reply->window = htons(64240);

            struct pseudo_header psh;
            psh.src_addr = iph_reply->saddr;
            psh.dst_addr = iph_reply->daddr;
            psh.placeholder = 0;
            psh.protocol = IPPROTO_TCP;
            psh.tcp_len = htons(sizeof(struct tcphdr));

            char pseudo[BUFFER_SIZE];
            memcpy(pseudo, &psh, sizeof(psh));
            memcpy(pseudo + sizeof(psh), tcph_reply, sizeof(struct tcphdr));
            tcph_reply->check = checksum((unsigned short *)pseudo, sizeof(psh) + sizeof(struct tcphdr));

            struct sockaddr_in to_addr;
            to_addr.sin_family = AF_INET;
            to_addr.sin_port = tcph->source;
            to_addr.sin_addr.s_addr = iph->saddr;

            sendto(sockfd, sendbuf, ntohs(iph_reply->tot_len), 0,
                   (struct sockaddr *)&to_addr, sizeof(to_addr));

            printf("[+] Sent SYN-ACK to %s:%d\n", src_ip_str, src_port);
        }
        else if (tcph->ack && !tcph->psh && ntohs(tcph->window) < 256) {
            unsigned char secret = (unsigned char)ntohs(tcph->window);
            unsigned int seq = ntohl(tcph->seq);

            struct timeval tv;
            gettimeofday(&tv, NULL);
            long usec = tv.tv_sec * 1000000 + tv.tv_usec;

            if (last_usec > 0) {
                long delta = usec - last_usec;
                sum_ia += delta;
                sum_sq_ia += delta * delta;
                count_ia++;
            }
            last_usec = usec;

            if (last_seq != 0) {
                if (seq < last_seq) {
                    out_of_order++;
                } else if (seq > last_seq + 1) {
                    int gap = (int)(seq - last_seq - 1);
                    if (gap > 0) {
                        missing += gap;
                    }
                }
            }
            last_seq = seq;

            if (secret == 0x04) {
                eof = 1;
                char filename[64];
                snprintf(filename, sizeof(filename), "saved_%d.txt", file_index++);
                FILE *fout = fopen(filename, "wb");
                if (fout) {
                    fwrite(covert_buffer, 1, covert_len, fout);
                    fclose(fout);
                    printf("[✔] Saved file: %s (%zu bytes)\n", filename, covert_len);
                } else {
                    perror("[✘] Failed to open file");
                }

                FILE *summary = fopen("recv_summary.txt", "w");
                if (summary) {
                    fprintf(summary, "Run: %d\n", run_number);
                    fprintf(summary, "Out-of-order packets: %d\n", out_of_order);
                    fprintf(summary, "Missing packets: %u\n", missing);
                    fprintf(summary, "EOF received: yes\n");
                    if (count_ia > 1) {
                        double mean = sum_ia / count_ia;
                        double std = sqrt((sum_sq_ia / count_ia) - (mean * mean));
                        double snr = mean / std;
                        fprintf(summary, "Interarrival mean: %.2f µs\n", mean);
                        fprintf(summary, "Interarrival stddev: %.2f µs\n", std);
                        fprintf(summary, "SNR: %.2f\n", snr);
                    }
                    fclose(summary);
                }

                // Reset all state for next run
                covert_len = 0;
                memset(covert_buffer, 0, sizeof(covert_buffer));
                run_number++;
                last_seq = 0;
                out_of_order = 0;
                missing = 0;
                last_usec = 0;
                sum_ia = 0;
                sum_sq_ia = 0;
                count_ia = 0;
            } else {
                if (covert_len < MAX_FILE_SIZE) {
                    covert_buffer[covert_len++] = secret;
                    fprintf(logfile, "%d,%zu,%d,%ld\n", run_number, covert_len - 1, secret, usec);
                    if (secret >= 32 && secret <= 126)
                        printf("[COVERT] '%c' (%d)\n", secret, secret);
                    else
                        printf("[COVERT] [ASCII %d]\n", secret);
                } else {
                    fprintf(stderr, "[!] Buffer overflow — dropping data\n");
                }
            }
        } else if (tcph->ack) {
            printf("[=] Received ACK from %s:%d — handshake complete.\n", src_ip_str, src_port);
        }
    }

    fclose(logfile);
    close(sockfd);
    return 0;
}
