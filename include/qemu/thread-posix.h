#ifndef QEMU_THREAD_POSIX_H
#define QEMU_THREAD_POSIX_H

#include <pthread.h>
#include <semaphore.h>
#include <mqueue.h>

typedef QemuMutex QemuRecMutex;
#define qemu_rec_mutex_destroy qemu_mutex_destroy
#define qemu_rec_mutex_lock qemu_mutex_lock
#define qemu_rec_mutex_try_lock qemu_mutex_try_lock
#define qemu_rec_mutex_unlock qemu_mutex_unlock

struct QemuMutex {
    pthread_mutex_t lock;
};

struct QemuCond {
    pthread_cond_t cond;
};

struct QemuSemaphore {
#if defined(__APPLE__) || defined(__NetBSD__)
    pthread_mutex_t lock;
    pthread_cond_t cond;
    unsigned int count;
#else
    sem_t sem;
#endif
};

struct QemuEvent {
#ifndef __linux__
    pthread_mutex_t lock;
    pthread_cond_t cond;
#endif
    unsigned value;
};

struct QemuThread {
    pthread_t thread;
};

//Avatar-specific
typedef struct {
    sem_t *sem;
} QemuAvatarSemaphore;

typedef struct {
    mqd_t mq;
} QemuAvatarMessageQueue;

void qemu_avatar_sem_wait(QemuAvatarSemaphore *sem);
void qemu_avatar_sem_post(QemuAvatarSemaphore *sem);
void qemu_avatar_sem_open(QemuAvatarSemaphore *sem, const char *name);

void qemu_avatar_mq_open_read(QemuAvatarMessageQueue *mq, const char *name);
void qemu_avatar_mq_open_write(QemuAvatarMessageQueue *mq, const char *name);
void qemu_avatar_mq_send(QemuAvatarMessageQueue *mq, void *msg, size_t len);
int qemu_avatar_mq_receive(QemuAvatarMessageQueue *mq, void *buffer, size_t len);

#endif
