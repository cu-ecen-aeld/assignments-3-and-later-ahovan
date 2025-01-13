#include "threading.h"

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

static const int US_IN_MS = 1000;

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;

    struct thread_data * const data = (struct thread_data * const) thread_param;

    data->thread_complete_success = false;

    usleep(data->wait_to_obtain_ms * US_IN_MS);

    int rc = pthread_mutex_lock(data->mutex);
    if (rc != 0) {
        ERROR_LOG("Failed to lock mutex: %s", strerror(rc));
        return thread_param;
    }

    usleep(data->wait_to_release_ms * US_IN_MS);

    rc = pthread_mutex_unlock(data->mutex);
    if (rc != 0) {
        ERROR_LOG("Failed to release mutex: %s", strerror(rc));
        return thread_param;
    }

    data->thread_complete_success = true;

    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

    struct thread_data * const data = (struct thread_data * const) malloc(sizeof(struct thread_data));
    if (data == NULL) {
        ERROR_LOG("Failed to allocate memory for thread_data: %s", strerror(errno));
        return false;
    }

    data->mutex = mutex;
    data->wait_to_obtain_ms = wait_to_obtain_ms;
    data->wait_to_release_ms = wait_to_release_ms;
    data->thread_complete_success = false;

    const int rc = pthread_create(thread, NULL, threadfunc, data);
    if (rc != 0) {
        ERROR_LOG("Failed to create thread: %s", strerror(rc));
        free(data);
        return false;
    }

    return true;
}

