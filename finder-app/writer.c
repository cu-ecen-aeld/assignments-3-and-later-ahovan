#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>


void exit_fail(const char * const msg) {
    const char * const err_msg = strerror(errno);

    char * const buf = malloc(strlen(msg) + strlen(err_msg) + 20);
    sprintf(buf, "%s; errno %d - %s", msg, errno, err_msg);
  
    syslog(LOG_ERR, "%s", buf);
    puts(buf); // duplicate message to current console stdout
  
    free(buf);

    closelog();
  
    exit(1);
}


int main(int argc, char *argv[])
{
    openlog(NULL, LOG_CONS, LOG_USER);
    if (errno != 0) {
	perror("Can't open log");
	return 1;
    }

    if (argc != 3) {
	exit_fail("Wrong number of arguments");
    }

    const char * const path_to_file = argv[1];
    const char * const content_to_write = argv[2];

    // I would prefer fopen() here, but we have to use syscalls, not C library functions...
    const int fd = open(path_to_file, (O_CREAT | O_RDWR), 0600); // 0600: set permissions at creating - rw for owner only
    if (fd == -1) {
	exit_fail("Can't open file");
    }

    const ssize_t bytes_to_write = strlen(content_to_write);
    const ssize_t n = write(fd, content_to_write, bytes_to_write);
    if (n == -1) {
	exit_fail("Can't write to file");
    }
    
    if (n != bytes_to_write) {
	exit_fail("Error writing to file");
    }

    if (close(fd) == -1) {
	exit_fail("Can't close file");
    }

    closelog();
    return 0;

}