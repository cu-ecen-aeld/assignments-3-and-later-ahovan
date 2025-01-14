#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <unistd.h>

static const char * const SERVER_ADDR = "127.0.0.1";
static const int SERVER_PORT = 9000;
static const int BACKLOG = 10;
static const ssize_t BUFFER_SIZE = 1024;

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

void wait_and_read_client(const int server_socket)
{
    syslog(LOG_INFO, "Waiting for client connection on %s:%d\n", SERVER_ADDR, SERVER_PORT);

    bool do_continue = true;
    while (do_continue) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        const int client_socket = accept(server_socket, (struct sockaddr * ) &client_addr, &client_addr_len);
        if (client_socket < 0) {
            exit_fail("Failed to accept client connection");
        }

        char client_ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN) == NULL) {
            exit_fail("Failed to convert client IP address to string");
        }

        syslog(LOG_INFO, "Accepted client connection from %s:%d\n", client_ip, client_addr.sin_port);
        char buffer[BUFFER_SIZE];
        const ssize_t read_bytes = recv(client_socket, buffer, sizeof(buffer), 0);
        if (read_bytes < 0) {
            exit_fail("Failed to read from client socket");
        } else if (read_bytes == 0) {
            // end of transmission
        } else {
            buffer[read_bytes] = '\0';
            syslog(LOG_INFO, "Received %zu bytes: \n%s\n", read_bytes, buffer);
            //TODO: find \n in buffer, if found, write/flush to file
        }

        close(client_socket);
        return;
    }

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
    addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        exit_fail("Failed to bind server socket");
    }

    if (listen(server_socket, BACKLOG) != 0) {
        exit_fail("Failed to listen on server socket");
    }

    wait_and_read_client(server_socket);


    close(server_socket);

    return 0;
}
