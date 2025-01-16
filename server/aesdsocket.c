#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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
static const ssize_t READ_CHUNK_SIZE = 1024;
static const char * const DUMP_DATA_FILE = "/var/tmp/aesdsocketdata";

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

void log_received_chunk(const char * const start, const ssize_t size)
{
    char * const log_string = malloc(size + 1 /* \0 */);
    if (log_string == NULL) {
        exit_fail("Failed to allocate memory for log string");
    }

    strncpy(log_string, start, size);
    log_string[size] = '\0';

    syslog(LOG_INFO, "Received %zu bytes: \n%s\n", size, log_string);

    free(log_string);
}

void process_client_connection(const int client_socket, const int dump_fd)
{
    char * buffer = NULL;
    ssize_t buffer_size = 0;
    ssize_t prev_dump_position = 0;
    bool do_continue = true;

    while (do_continue) {
        buffer = realloc(buffer, buffer_size + READ_CHUNK_SIZE);
        if (buffer == NULL) {
            exit_fail("Failed to (re)allocate memory for read buffer");
        }

        const ssize_t read_bytes = recv(client_socket, buffer + buffer_size, READ_CHUNK_SIZE, 0);

        if (read_bytes < 0) {
            exit_fail("Failed to read from client socket");
        } else if (read_bytes == 0) { // end of transmission from client side
            do_continue = false;
        } else {
            const char * const new_portion = buffer + buffer_size;
            buffer_size += read_bytes;

            log_received_chunk(new_portion, read_bytes);

            if (buffer[buffer_size - 1] == '\n') { // it is time to dump a portion to file
                const ssize_t bytes_to_write = buffer_size - prev_dump_position;
                const ssize_t written_bytes = write(dump_fd, buffer + prev_dump_position, bytes_to_write);
                if (written_bytes != bytes_to_write) {
                    //printf("written_bytes: %ld, read_bytes: %ld\n", written_bytes, read_bytes);
                    exit_fail("Failed to write to dump data file");
                }

                sync();

                prev_dump_position += read_bytes;
            }
        }
    }

    // TODO: sent buffer back to client, free memory
    free(buffer);
}

void do_server_loop(const int server_socket, const int dump_fd)
{
    syslog(LOG_INFO, "Waiting for client connection on %s:%d\n", SERVER_ADDR, SERVER_PORT);

    while (true) {
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

        process_client_connection(client_socket, dump_fd);

        if (close(client_socket) == -1) {
            exit_fail("Failed to close client socket");
        }
        syslog(LOG_INFO, "Close connection from %s:%d\n", client_ip, client_addr.sin_port);
    }
}

const int init_server()
{
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

    return server_socket;
}

int main(int argc, char ** argv)
{
    const bool daemon = (argc > 1 && strcmp(argv[1], "-d") == 0);

    // duplicate to console if not daemon
    const int duplicate_to_stderr = daemon ? 0 : LOG_PERROR;

    openlog("aesdsocket", LOG_PID | LOG_CONS | duplicate_to_stderr, LOG_USER);

    const int dump_fd = open(DUMP_DATA_FILE, O_RDWR | O_TRUNC | O_CREAT, 0644);
    if (dump_fd < 0) {
        exit_fail("Failed to open dump data file");
    }

    const int server_socket = init_server();

    do_server_loop(server_socket, dump_fd);

    if (close(server_socket) == -1) {
        exit_fail("Failed to close server socket");
    }

    if (close(server_socket) == -1) {
        exit_fail("Failed to close dump data file");
    }

    return 0;
}
