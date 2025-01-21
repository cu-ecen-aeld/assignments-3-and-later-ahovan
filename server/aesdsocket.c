#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
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
static const int TIME_LOGGING_PERIOD_SEC = 10;

// very bad idea to keep such things in global variables, but we need to close them in signal handler 
static int server_socket = -1;
static int client_socket = -1;
static int dump_fd = -1;
pthread_mutex_t dump_file_mutex;

//TODO: put time_logging_thread to list of threads instead
static pthread_t time_logging_thread = -1;

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

    // ??? at which point of cleanup() should I wait for threads to finish and destroy mutex?
    // ??? how to check that mutex was initialized?
    pthread_mutex_destroy(&dump_file_mutex);

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

    // prevent changes in file between lseek() and write() that may come from other threads 
    pthread_mutex_lock(&dump_file_mutex);
    off_t file_size = lseek(dump_fd, 0, SEEK_END);
    const ssize_t written_bytes = write(dump_fd, buffer, buffer_size);
    pthread_mutex_unlock(&dump_file_mutex);
    
    if (written_bytes != buffer_size) {
        exit_fail("Failed to write to dump data file");
    }

    sync();

    file_size += buffer_size;

    syslog(LOG_INFO, "Sending %zu bytes back to client\n", file_size);

    if (lseek(dump_fd, 0, SEEK_SET) < 0) {
        exit_fail("Failed to rewind to begin of dump data file");
    }

    // at this point we are not aware of file changes from other threads
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

    const int reuse = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        exit_fail("Failed to set SO_REUSEADDR for server socket");
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

void start_daemon(void)
{
    const pid_t pid = fork();
    if (pid == -1) {
        exit_fail("Failed to fork");
    }

    if (pid != 0) { // parent process
        exit(0);
    }

    if (setsid() == -1) {
        exit_fail("Failed to set process group ID");
    }

    if (chdir("/") == -1) {
        exit_fail("Failed to set working directory for daemon");
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

void * do_time_logging(void *)
{
    while (true) {
        const time_t now = time(NULL);
        const struct tm * const now_tm = localtime(&now);
        if (now_tm == NULL) {
            exit_fail("Failed to get current time");
        }

        char buffer[64];
        const ssize_t buffer_size = strftime(buffer, sizeof(buffer), "timestamp:%a, %d %b %Y %H:%M:%S %z\n", now_tm);
        if (buffer_size < 0) {
            exit_fail("Failed to format current time");
        }

        syslog(LOG_INFO, "Logging time %s\n", buffer);

        pthread_mutex_lock(&dump_file_mutex);
        const ssize_t written_bytes = write(dump_fd, buffer, buffer_size);
        pthread_mutex_unlock(&dump_file_mutex);

        if (written_bytes != buffer_size) {
            exit_fail("Failed to write timestamp to dump data file");
        }

        // This approach is described in R. Love's Linux System Programming book.
        // Page 383 contains rationale for using nanosleep() vs other methods.
        struct timespec req = { .tv_sec = TIME_LOGGING_PERIOD_SEC, .tv_nsec = 0 };
        struct timespec rem, * a = &req, * b = &rem;
        while (nanosleep (a, b) && errno == EINTR) {
            struct timespec * tmp = a;
            a = b;
            b = tmp;
        }
    }

    return NULL;
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

    if (pthread_mutex_init(&dump_file_mutex, NULL) != 0) {
        exit_fail("Failed to initialize mutex for dump file");
    }

    if (daemon) {
        start_daemon();
    }

    if (pthread_create(&time_logging_thread, NULL, do_time_logging, NULL) != 0) {
        exit_fail("Failed to create time logging thread");
    }

    do_server_loop();

    // actually will never get here, but just for sake of completeness
    cleanup();

    return 0;
}
