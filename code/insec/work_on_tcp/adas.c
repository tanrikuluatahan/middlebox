if (tcph->syn && !tcph->ack) {
    printf("[1] SYN from %s:%d\n", src_ip_str, src_port);

    // 🧠 Save the sender IP early to avoid pointer reuse bugs
    uint32_t sender_ip = iph->saddr;

    // Build SYN-ACK packet
    char sendbuf[BUFFER_SIZE];
    memset(sendbuf, 0, BUFFER_SIZE);
    struct iphdr *iph_reply = (struct iphdr *)sendbuf;
    struct tcphdr *tcph_reply = (struct tcphdr *)(sendbuf + sizeof(struct iphdr));

    iph_reply->ihl = 5;
    iph_reply->version = 4;
    iph_reply->tos = 0;
    iph_reply->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph_reply->id = htons(rand() % 65535);
    iph_reply->frag_off = 0;
    iph_reply->ttl = 64;
    iph_reply->protocol = IPPROTO_TCP;
    iph_reply->saddr = inet_addr(host_ip);  // our IP
    iph_reply->daddr = sender_ip;           // saved source IP from sender
    iph_reply->check = 0;
    iph_reply->check = checksum((unsigned short *)iph_reply, sizeof(struct iphdr));

    tcph_reply->source = tcph->dest;
    tcph_reply->dest = tcph->source;
    tcph_reply->seq = htonl(1000);
    tcph_reply->ack_seq = htonl(ntohl(tcph->seq) + 1);
    tcph_reply->doff = 5;
    tcph_reply->syn = 1;
    tcph_reply->ack = 1;
    tcph_reply->window = htons(64240);
    tcph_reply->check = 0;

    // Checksum with pseudo header
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
    to_addr.sin_addr.s_addr = sender_ip;

    // Safer logging
    char s_ip[INET_ADDRSTRLEN], d_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph_reply->saddr, s_ip, sizeof(s_ip));
    inet_ntop(AF_INET, &iph_reply->daddr, d_ip, sizeof(d_ip));

    printf("[DBG] Sending SYN-ACK: src=%s:%d → dst=%s:%d\n",
           s_ip, ntohs(tcph_reply->source),
           d_ip, ntohs(tcph_reply->dest));
    printf("[DBG] OUTGOING FLAGS: SYN=%d ACK=%d SEQ=%u ACK_SEQ=%u\n",
           tcph_reply->syn, tcph_reply->ack,
           ntohl(tcph_reply->seq), ntohl(tcph_reply->ack_seq));

    sendto(sockfd, sendbuf, ntohs(iph_reply->tot_len), 0,
           (struct sockaddr *)&to_addr, sizeof(to_addr));

    printf("[2] Sent SYN-ACK\n");
    handshake_complete = 0;  // Reset handshake state
}
