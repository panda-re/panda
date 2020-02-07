#include "time.h"

#include "qemu/osdep.h"
#include "sysemu/sysemu.h"

#include "hw/avatar/avatar_posix.h"

static void error_exit(int err, const char *msg)
{
    fprintf(stderr, "qemu: %s: %s\n", msg, strerror(err));
    abort();
}

void qemu_avatar_sem_open(QemuAvatarSemaphore *sem, const char *name)
{
#if defined(__APPLE__) || defined(__NetBSD__)
#else
    sem_unlink(name);
    sem_t *rc = sem_open(name, O_CREAT, S_IRUSR | S_IWUSR, 1);

    if(rc == SEM_FAILED) {
        error_exit(errno, __func__);
    }

    sem->sem = rc;
#endif
}

void qemu_avatar_sem_wait(QemuAvatarSemaphore *sem)
{
#if defined(__APPLE__) || defined(__NetBSD__)
#else
    int rc = sem_wait(sem->sem);
    if (rc < 0) {
        error_exit(errno, __func__);
    }
#endif
}

void qemu_avatar_sem_post(QemuAvatarSemaphore *sem)
{
#if defined(__APPLE__) || defined(__NetBSD__)
#else
    int rc = sem_post(sem->sem);
    if (rc < 0) {
        error_exit(errno, __func__);
    }
#endif
}

void qemu_avatar_mq_open_read(QemuAvatarMessageQueue *mq, const char *name, size_t msg_size)
{
#if defined(__APPLE__) || defined(__NetBSD__)
#else
    mq_unlink(name);

    struct mq_attr attr;
    attr.mq_flags = O_NONBLOCK;
    attr.mq_msgsize = msg_size;
    attr.mq_maxmsg = 10;
    attr.mq_curmsgs = 0;

    mqd_t m = mq_open(name, O_CREAT | O_EXCL | O_RDONLY, 0600, &attr);

    if(m == -1)
    {
        error_exit(errno, __func__);
    }

    mq->mq = m;
#endif
}

void qemu_avatar_mq_open_write(QemuAvatarMessageQueue *mq, const char *name, size_t msg_size)
{
#if defined(__APPLE__) || defined(__NetBSD__)
#else
    mq_unlink(name);

    struct mq_attr attr;
    attr.mq_msgsize = msg_size;
    attr.mq_maxmsg = 10;
    attr.mq_curmsgs = 0;

    mqd_t m = mq_open(name, O_CREAT | O_EXCL | O_WRONLY, 0600, &attr);
 
    if(m == -1)
    {
        error_exit(errno, __func__);
    }

    mq->mq = m;
#endif
}

void qemu_avatar_mq_send(QemuAvatarMessageQueue *mq, void *msg, size_t len)
{
#if defined(__APPLE__) || defined(__NetBSD__)
#else
    int rc = mq_send(mq->mq, msg, len, 0);

    if (rc < 0)
    {
        error_exit(errno, __func__);
    }
#endif
}

int qemu_avatar_mq_receive(QemuAvatarMessageQueue *mq, void *buffer, size_t len)
{
#if defined(__APPLE__) || defined(__NetBSD__)
#else
    struct timespec tm;
    int rc = -1;

    clock_gettime(CLOCK_REALTIME, &tm);
    
    /* In corner cases, a shutdown of qemu is requested while an mq_receive
     * would block. Hence, the repeated mq_timedreceive */
    while(!qemu_shutdown_requested_get()){

      tm.tv_sec += 1;

      int rc = mq_timedreceive(mq->mq, buffer, len, NULL, &tm);

      if(rc>0){
          break;
      }

      if (rc < 0 && errno == ETIMEDOUT)
      {
        continue;
      }
      else if (rc < 0 && errno != EAGAIN)
      {
        error_exit(errno, __func__);
      }
    }

    return rc;
#endif
}

int qemu_avatar_mq_get_fd(QemuAvatarMessageQueue *mq)
{
    return mq->mq;
}
