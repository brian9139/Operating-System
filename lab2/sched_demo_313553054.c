#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>


#define handle_error_en(en, msg) \
    do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

typedef struct {
    int id;
    int policy;
    int priority;
    double time_wait;
} thread_info;

pthread_barrier_t barrier;

// void busy_wait(double seconds) {
//     struct timeval start, current;
//     gettimeofday(&start, NULL);
//     while (1) {
//         gettimeofday(&current, NULL);
//         double elapsed = (current.tv_sec - start.tv_sec) + 
//                          (current.tv_usec - start.tv_usec) / 1e6;
//         if (elapsed >= seconds) break;
//     }
// }

void busy_wait(double seconds) {
    struct timespec start, current;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);  // Get start time based on CPU time for the thread

    while (1) {
        clock_gettime(CLOCK_THREAD_CPUTIME_ID, &current);  // Get the current CPU time for the thread

        double elapsed = (current.tv_sec - start.tv_sec) +
                         (current.tv_nsec - start.tv_nsec) / 1e9;  // Convert nanoseconds to seconds

        if (elapsed >= seconds) break;
    }
}


void *thread_func(void *arg) {
    thread_info *tinfo = (thread_info *) arg;

    pthread_barrier_wait(&barrier); // Wait for all threads to be ready

    for (int i = 0; i < 3; i++) {
        printf("Thread %d is starting\n", tinfo->id);
        busy_wait(tinfo->time_wait); // Busy wait for specified time
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int opt, num_threads = 0;
    double time_wait = 0.0;
    char *schedules = NULL, *priorities = NULL;
    pthread_t *threads;
    thread_info *tinfo;
    pthread_attr_t attr;
    cpu_set_t cpuset;

    while ((opt = getopt(argc, argv, "n:t:s:p:")) != -1) {
        switch (opt) {
        case 'n': num_threads = atoi(optarg); break;
        case 't': time_wait = atof(optarg); break;
        case 's': schedules = strdup(optarg); break;
        case 'p': priorities = strdup(optarg); break;
        default: fprintf(stderr, "Usage: %s -n <num_threads> -t <time_wait> -s <schedules> -p <priorities>\n", argv[0]);
                 exit(EXIT_FAILURE);
        }
    }

    // Parse scheduling policies and priorities
    char *policy_tokens[num_threads];
    char *priority_tokens[num_threads];
    char *token = strtok(schedules, ",");
    for (int i = 0; i < num_threads && token; i++) {
        policy_tokens[i] = token;
        token = strtok(NULL, ",");
    }

    token = strtok(priorities, ",");
    for (int i = 0; i < num_threads && token; i++) {
        priority_tokens[i] = token;
        token = strtok(NULL, ",");
    }

    threads = malloc(num_threads * sizeof(pthread_t));
    tinfo = malloc(num_threads * sizeof(thread_info));

    pthread_barrier_init(&barrier, NULL, num_threads);

    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);

    for (int i = 0; i < num_threads; i++) {
        tinfo[i].id = i;
        tinfo[i].time_wait = time_wait;

        // Set policy and priority
        if (strcmp(policy_tokens[i], "NORMAL") == 0) {
            tinfo[i].policy = SCHED_OTHER;
            tinfo[i].priority = 0;
        } else if (strcmp(policy_tokens[i], "FIFO") == 0) {
            tinfo[i].policy = SCHED_FIFO;
            tinfo[i].priority = atoi(priority_tokens[i]);
        }

        pthread_attr_init(&attr);
        pthread_attr_setinheritsched(&attr, tinfo[i].policy);
        pthread_attr_setschedpolicy(&attr, tinfo[i].policy);
        
        struct sched_param param;
        param.sched_priority = tinfo[i].priority;
        pthread_attr_setschedparam(&attr, &param);
        
        // Set CPU affinity
        pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset);

        if (pthread_create(&threads[i], &attr, thread_func, &tinfo[i]) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    // Wait for all threads to finish
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(tinfo);
    pthread_barrier_destroy(&barrier);
    return 0;
}
