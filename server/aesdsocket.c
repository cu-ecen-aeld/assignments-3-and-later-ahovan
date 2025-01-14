#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <unistd.h>


void exit_fail(const char * const msg) {
    const char * const err_msg = strerror(errno);

    char * const buf = malloc(strlen(msg) + strlen(err_msg) + 20);
    sprintf(buf, "%s; errno %d - %s", msg, errno, err_msg);

    // duplicated to stderr automatically if not daemon
    syslog(LOG_ERR, "%s", buf);

    free(buf);
    closelog();
    exit(-1);
}


int main(int argc, char ** argv)
{
    const bool daemon = (argc > 1 && strcmp(argv[1], "-d") == 0);

    // duplicate to console if not daemon
    const int duplicate_to_stderr = daemon ? 0 : LOG_PERROR;

    openlog("aesdsocket", LOG_PID | LOG_CONS | duplicate_to_stderr, LOG_USER);

    const int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        exit_fail("Failed to create socket");
    }

    // TODO: give a try to getaddrinfo() instead old-school way
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(9000);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        exit_fail("Failed to bind server socket");
    }

    if (listen(server_socket, 10) != 0) {
        exit_fail("Failed to listen on server socket");
    }

    bool do_continue = true;
    while (do_continue) {
        // TODO: add client_addr and log it
        const int client_socket = accept(server_socket, NULL, NULL);
        if (client_socket < 0) {
            exit_fail("Failed to accept client connection");
        }

        char buffer[1024];
        const ssize_t read_bytes = recv(client_socket, buffer, sizeof(buffer), 0);
        if (read_bytes < 0) {
            perror("Failed to read from client socket");
            // cleanup/exit/next iteration???
        } else if (read_bytes == 0) {
            // end of transmission
        } else {
            buffer[read_bytes] = '\0';
            syslog(LOG_INFO, "Received %zu bytes: %s\n", read_bytes, buffer);
        }

        close(client_socket);
    }

    return 0;
}
