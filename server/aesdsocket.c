#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <unistd.h>

static const char * const SERVER_ADDR = "127.0.0.1";
static const int SERVER_PORT = 9000;
static const int BACKLOG = 10;
static const ssize_t READ_CHUNK_SIZE = 1024;
static const char * const DUMP_DATA_FILE = "/var/tmp/aesdsocketdata";

// very bad idea to keep such things in global variables, but we need to close them in signal handler 
static int server_socket = -1;
static int client_socket = -1;
static int dump_fd = -1;


void cleanup(void)
{
    if (server_socket != -1) {
        close(server_socket);
    }
    if (client_socket != -1) {
        close(server_socket);
    }

    if (dump_fd != -1) {
        close(dump_fd);
    }

    closelog();
}

void exit_fail(const char * const msg) {
    const char * const err_msg = strerror(errno);

    char * const buf = malloc(strlen(msg) + strlen(err_msg) + 20);
    sprintf(buf, "%s; errno %d - %s", msg, errno, err_msg);

    // duplicated to stderr automatically if not daemon
    syslog(LOG_ERR, "%s", buf);

    free(buf);

    cleanup();

    exit(-1);
}

void signal_handler(const int signum)
{
    syslog(LOG_INFO, "Caught signal %d, freeing up resources and exiting\n", signum);
    cleanup();
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

void process_client_connection(void)
{
    char * buffer = NULL;
    ssize_t buffer_size = 0;

    while (true) {
        buffer = realloc(buffer, buffer_size + READ_CHUNK_SIZE);
        if (buffer == NULL) {
            exit_fail("Failed to (re)allocate memory for read buffer");
        }

        const ssize_t read_bytes = recv(client_socket, buffer + buffer_size, READ_CHUNK_SIZE, 0);

        if (read_bytes < 0) {
            exit_fail("Failed to read from client socket");
        } else if (read_bytes == 0) { // end of transmission from client side
            break;
        } else {
            const char * const new_portion = buffer + buffer_size;
            buffer_size += read_bytes;

            log_received_chunk(new_portion, read_bytes);

            if (buffer[buffer_size - 1] == '\n') {
                break;
            }
        }
    }

    off_t file_size = lseek(dump_fd, 0, SEEK_END);

    const ssize_t written_bytes = write(dump_fd, buffer, buffer_size);
    if (written_bytes != buffer_size) {
        exit_fail("Failed to write to dump data file");
    }

    sync();

    file_size += buffer_size;

    syslog(LOG_INFO, "Sending %zu bytes back to client\n", file_size);

    if (lseek(dump_fd, 0, SEEK_SET) < 0) {
        exit_fail("Failed to rewind to begin of dump data file");
    }

    const ssize_t sent_bytes = sendfile(client_socket, dump_fd, NULL, file_size);

    free(buffer);

    if (sent_bytes != file_size) {
        exit_fail("Failed to send data back to client");
    }
}

void do_server_loop(void)
{
    syslog(LOG_INFO, "Waiting for client connection on %s:%d\n", SERVER_ADDR, SERVER_PORT);

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr * ) &client_addr, &client_addr_len);
        if (client_socket < 0) {
            exit_fail("Failed to accept client connection");
        }

        char client_ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN) == NULL) {
            exit_fail("Failed to convert client IP address to string");
        }

        syslog(LOG_INFO, "Accepted client connection from %s:%d\n", client_ip, client_addr.sin_port);

        process_client_connection();

        if (close(client_socket) == -1) {
            exit_fail("Failed to close client socket");
        }
        client_socket = -1;
        syslog(LOG_INFO, "Close connection from %s:%d\n", client_ip, client_addr.sin_port);
    }
}

void init_server(void)
{
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
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
}

int main(int argc, char ** argv)
{
    const bool daemon = (argc > 1 && strcmp(argv[1], "-d") == 0);

    // duplicate to console if not daemon
    const int duplicate_to_stderr = daemon ? 0 : LOG_PERROR;

    openlog("aesdsocket", LOG_PID | LOG_CONS | duplicate_to_stderr, LOG_USER);

    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        exit_fail("Failed to install SIGINT handler");
    }

    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
        exit_fail("Failed to install SIGTERM handler");
    }

    dump_fd = open(DUMP_DATA_FILE, O_RDWR | O_TRUNC | O_CREAT, 0644);
    if (dump_fd < 0) {
        exit_fail("Failed to open dump data file");
    }

    init_server();

    do_server_loop();

    // actually will never get here, but just for sake of completeness
    cleanup();

    return 0;
}
