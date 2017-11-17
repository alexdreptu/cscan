/*
 * MIT License
 *
 * Copyright (c) 2008 Alexandru Dreptu
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * Simple TCP port scanner using non-blocking sockets.
 * Compiling: gcc -Wall -std=gnu11 cscan.c -o cscan
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_SOCKS 1024
#define STATUS_NONE 1
#define STATUS_CONNECTING 2

struct connection {
    int sock;
    int status;
    time_t conn_time;
    struct sockaddr_in caddr;
};

struct connection conns[MAX_SOCKS];
FILE *logfd;
unsigned int timeout = 5;
unsigned int socks_nr = 256;
int verbose = 0;
unsigned long found = 0;

// clean connection structure
void clean_struct(struct connection *sc) {
    if (sc->sock) {
        shutdown(sc->sock, SHUT_RDWR);
        close(sc->sock);
        sc->sock = 0;
    }
    sc->status = STATUS_NONE;
    sc->conn_time = 0;
    memset(&(sc->caddr), 0, sizeof(struct sockaddr));
}

int connect_to(struct connection *sc) {
    int sock, flags, flags_old;

    // create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Cannot create socket");
        return -1;
    }

    // set non-blocking mode
    flags_old = fcntl(sock, F_GETFL, 0);
    flags = flags_old;
    flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) == -1) {
        perror("Cannot set non-blocking socket");
        return -1;
    }

    // connect to given host
    connect(sock, (struct sockaddr *)&(sc->caddr), sizeof(struct sockaddr));
    sc->sock = sock;
    sc->status = STATUS_CONNECTING;
    sc->conn_time = time(0);

    return 0;
}

void verif_sock(struct connection *sc) {
    int conret;
    // timeout for connecting socket
    if ((sc->status == STATUS_CONNECTING) &&
        ((time(0) - sc->conn_time) >= timeout)) {
        clean_struct(&(*sc));
        return;
    }

    // connect again, parse errors and log the result
    conret = connect(sc->sock, (struct sockaddr *)&(sc->caddr),
                     sizeof(struct sockaddr));
    if ((conret == -1) && (errno != EALREADY) && (errno != EINPROGRESS))
        clean_struct(&(*sc));
    else if (((conret == -1) && (errno == EISCONN)) || (conret == 0)) {
        if (logfd)
            fprintf(logfd, "%s:%u\n", inet_ntoa(sc->caddr.sin_addr),
                    ntohs(sc->caddr.sin_port));
        if ((verbose && logfd) || (!logfd))
            printf("Open %s:%u    \n", inet_ntoa(sc->caddr.sin_addr),
                   ntohs(sc->caddr.sin_port));
        fflush(logfd);
        found++;
        clean_struct(&(*sc));
    }

    return;
}

void usage(char *this) {
    printf("\n"
           "  Simple TCP Port Scanner\n"
           "  Compilation Time: %s %s\n"
           "\n"
           "  Options:\n"
           "    -h <n>   Host/s [e.g. 192.168.1.0/24]\n"
           "    -o <n>   Output file\n"
           "    -p <n>   Port/s to scan.\n"
           "    -t <n>   Timeout seconds [default 5]\n"
           "    -s <n>   Parallel sockets [default 256]\n"
           "    -m <n>   Internal sleep time [default 500ms]\n"
           "    -v       Verbose.\n"
           "\n"
           "  Examples:\n"
           "    %s -p 1-1000 -v -s 512 -t 2 -h 192.168.0.2\n"
           "    %s -p 22 -o ip.log -u 500 -h 192.168.0.0/16\n"
           "\n",
           __DATE__, __TIME__, this, this);
    exit(0);
}

void _cleanup(int none) {
    int x;
    puts("Ok, cleaning up, please wait...\n");
    for (x = 0; x < MAX_SOCKS; x++) {
        verif_sock(&conns[x]);
        clean_struct(&conns[x]);
    }
    puts("Done.\n");
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    unsigned long n_ip, h_ip, current_ip, end_ip;
    unsigned long mask = 0xffffffff;
    char *mask_slash, *port_char;
    char hosts[256] = "", outfile[256] = "", port_range[64] = "";
    unsigned long start_port, current_port, end_port;
    int x, verif_sock_time = 500;
    unsigned long progress, etc, _total;
    float total;
    time_t start_time = time(0);
    struct in_addr plm;

    if (argc < 2) usage(argv[0]);

    // parse cmd line
    while ((x = getopt(argc, argv, "h:p:s:o:m:t:v")) != -1) {
        switch (x) {
        case 'h': strcpy(hosts, optarg); break;
        case 'm': verif_sock_time = atoi(optarg); break;
        case 'o': strcpy(outfile, optarg); break;
        case 't': timeout = atoi(optarg); break;
        case 'v': verbose = 1; break;
        case 'p': strcpy(port_range, optarg); break;
        case 's': socks_nr = atoi(optarg); break;
        default: printf("Try `%s' for usage.\n", argv[0]); exit(0);
        }
    }

    // set intrerrupt signal
    signal(SIGINT, _cleanup);

    // calculate netmask (ip range)
    if ((mask_slash = strchr(hosts, '/'))) {
        *mask_slash = 0;
        mask_slash++;
    }
    if (mask_slash) mask <<= (32 - atol(mask_slash));

    n_ip = inet_addr(hosts);
    h_ip = ntohl(n_ip);
    end_ip = h_ip | ~mask;
    current_ip = h_ip;

    // calculate port range
    port_char = strchr(port_range, '-');
    if (port_char) {
        *port_char = 0;
        port_char++;
        end_port = atol(port_char);
    }
    start_port = atol(port_range);
    current_port = start_port;
    if (!port_char) end_port = start_port;
    if (start_port > end_port) {
        fprintf(stderr, "Invalid port range.\n");
        exit(EXIT_FAILURE);
    }

    // clean struct array
    for (x = 0; x < MAX_SOCKS; x++) clean_struct(&conns[x]);

    // calculate total connections
    etc = end_port - start_port + 1;
    total = end_ip - h_ip + 1.00000;
    total *= etc;
    progress = 0;
    _total = end_ip - h_ip + 1;
    _total *= etc;

    // verify some stuff
    if (socks_nr > MAX_SOCKS) {
        fprintf(stderr, "Max sockets number is 1024.\n");
        exit(EXIT_FAILURE);
    }
    if (socks_nr > _total) socks_nr = _total;
    if (inet_addr(hosts) == -1) {
        fprintf(stderr, "Invalid IP address given.\n");
        exit(EXIT_FAILURE);
    }
    if ((end_port > 65534) || (end_port < 1)) {
        fprintf(stderr, "Port must be a number within 1-65534\n");
        exit(EXIT_FAILURE);
    }
    if ((verif_sock_time / 1000) > timeout) {
        fprintf(stderr, "Internal sleep time cannot be above timeout value.\n");
        exit(EXIT_FAILURE);
    }

    // where to log
    if (*outfile) {
        logfd = fopen(outfile, "a+");
        if (!logfd) {
            perror("Cannot open/create log file");
            exit(EXIT_FAILURE);
        }
    }

    if (verbose) {
        putchar('\n');
        plm.s_addr = htonl(h_ip);
        printf("Total hosts to scan %lu (%s - ", end_ip - h_ip + 1,
               inet_ntoa(plm));
        plm.s_addr = htonl(end_ip);
        printf("%s)\n", inet_ntoa(plm));
        printf("Total ports to scan %lu (range %u - %u)\n", _total,
               (unsigned short)start_port, (unsigned short)end_port);
        etc = ((_total / socks_nr) * timeout) + timeout;
        printf("Estimated time %lu hours, %lu mins, %lu secs.\n", etc / 3600,
               etc % 3600 ? (etc % 3600) / 60 : etc % 60,
               etc % 3600 ? (etc % 3600) % 60 : etc % 60);
        putchar('\n');
    }

    while (current_ip <= end_ip) {
        for (x = 0; x < socks_nr; x++) {
            // if array index is unused, we'll use it
            if (conns[x].status == STATUS_NONE) {
                conns[x].caddr.sin_addr.s_addr = htonl(current_ip);
                conns[x].caddr.sin_port = htons((unsigned short)current_port);
                conns[x].caddr.sin_family = AF_INET;
                if (connect_to(&conns[x]) == -1) {
                    fprintf(stderr,
                            "Oops, try with `-s < %u'. Sleeping 10secs.\n",
                            socks_nr);
                    sleep(10);
                    break;
                }
                progress++;
                fprintf(stderr, "Open %lu [%0.2f%%]\r", found,
                        (progress / total) * 100);
                fflush(stdout);
                current_port++;
                if (current_port > end_port) {
                    current_ip++;
                    current_port = start_port;
                }
            }
            if (current_ip > end_ip) break;
        }

        // prevent 100% cpu usage
        usleep(verif_sock_time * 1000);
        for (x = 0; x < socks_nr; x++) verif_sock(&conns[x]);
    }

    putchar('\n');

    // wait for all socks
    if (verbose) printf("Waiting remaining sockets...\n");
    sleep(timeout);
    for (x = 0; x < socks_nr; x++) {
        verif_sock(&conns[x]);
        clean_struct(&conns[x]);
    }

    printf("Open %lu [Done]\n", found);
    if (verbose) {
        etc = time(0) - start_time;
        printf("Scan completed in %lu hours, %lu min, %lu secs.\n", etc / 3600,
               etc % 3600 ? (etc % 3600) / 60 : etc % 60,
               etc % 3600 ? (etc % 3600) % 60 : etc % 60);
    }

    if (logfd) fclose(logfd);
    return 0;
}
