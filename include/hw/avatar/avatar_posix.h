#ifndef AVATAR_POSIX_H
#define AVATAR_POSIX_H

#include <semaphore.h>
#include <mqueue.h>

typedef struct {
    sem_t *sem;
} QemuAvatarSemaphore;

typedef struct {
    mqd_t mq;
} QemuAvatarMessageQueue;

void qemu_avatar_sem_wait(QemuAvatarSemaphore *sem);
void qemu_avatar_sem_post(QemuAvatarSemaphore *sem);
void qemu_avatar_sem_open(QemuAvatarSemaphore *sem, const char *name);

void qemu_avatar_mq_open_read(QemuAvatarMessageQueue *mq, const char *name, size_t msg_size);
void qemu_avatar_mq_open_write(QemuAvatarMessageQueue *mq, const char *name, size_t msg_size);
void qemu_avatar_mq_send(QemuAvatarMessageQueue *mq, void *msg, size_t len);
int qemu_avatar_mq_receive(QemuAvatarMessageQueue *mq, void *buffer, size_t len);
int qemu_avatar_mq_get_fd(QemuAvatarMessageQueue *mq);


#endif
