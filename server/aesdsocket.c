#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


int main(int argc, char ** argv)
{
    const int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Failed to create socket");
        return -1;
    }

    // TODO: give a try to getaddrinfo() instead old-school way
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(9000);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        perror("Failed to bind server socket");
        return -1;
    }

    if (listen(server_socket, 10) != 0) {
        perror("Failed to listen on server socket");
        return -1;
    }

    bool do_continue = true;
    while (do_continue) {
        // TODO: add client_addr and log it
        const int client_socket = accept(server_socket, NULL, NULL);
        if (client_socket < 0) {
            perror("Failed to accept client connection");
            return -1;
        }

        char buffer[1024];
        const ssize_t read_bytes = recv(client_socket, buffer, sizeof(buffer), 0);
        if (read_bytes < 0) {
            perror("Failed to read from client socket");
            // cleanup/exit/next iteration???
        } else if (read_bytes == 0) {
            // end of transmission
        } else {
            buffer [read_bytes] = '\0';
            printf("Received %zu bytes: %s\n", read_bytes, buffer);
        }

        close(client_socket);
    }

    return 0;
}
