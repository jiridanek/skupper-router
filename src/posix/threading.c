/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

//
// Enable debug for asserts in this module regardless of what the project-wide
// setting is.
//
#undef NDEBUG

#include "qpid/dispatch/threading.h"

#include "qpid/dispatch/ctools.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <syscall.h>
#include <unistd.h>

// https://lwn.net/Articles/823513/

// can have spurious wakeup?

static long futex(uint32_t *uaddr, int futex_op, uint32_t val,
      const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val,
                   timeout, uaddr2, val3);
}

/* Acquire the futex pointed to by 'futexp': wait for its value to
   become 1, and then set the value to 0. */

static void
fwait(uint32_t *futexp)
{
    long s;

    /* atomic_compare_exchange_strong(ptr, oldval, newval)
       atomically performs the equivalent of:

           if (*ptr == *oldval)
               *ptr = newval;

       It returns true if the test yielded true and *ptr was updated. */

    while (1) {

        /* Is the futex available? */
        const uint32_t one = 1;
        if (atomic_compare_exchange_strong(futexp, &one, 0))
            break;      /* Yes */

        /* Futex is not available; wait. */

        s = futex(futexp, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
        assert(s != -1 || errno == EAGAIN);
    }
}



/* Release the futex pointed to by 'futexp': if the futex currently
   has the value 0, set its value to 1 and the wake any futex waiters,
   so that if the peer is blocked in fwait(), it can proceed. */

static void fpost(uint32_t *futexp)
{
    long s;

    /* atomic_compare_exchange_strong() was described
       in comments above. */

    const uint32_t zero = 0;
    if (atomic_compare_exchange_strong(futexp, &zero, 1)) {
        s = futex(futexp, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
        assert(s != -1);
    }
}

void sys_mutex(sys_mutex_t *mutex)
{
    atomic_init(mutex, 0);
}


void sys_mutex_free(sys_mutex_t *mutex)
{
    (void) mutex;
}


void sys_mutex_lock(sys_mutex_t  *mutex)
{
    assert(*mutex == 0 || *mutex == 1 || *mutex == 2);

    long s;

    /* atomic_compare_exchange_strong(ptr, oldval, newval)
       atomically performs the equivalent of:

           if (*ptr == *oldval)
               *ptr = newval;

       It returns true if the test yielded true and *ptr was updated. */

    while (1) {
        /* Is the futex available? */
        const uint32_t zero = 0;
        const uint32_t one = 1;

        if (atomic_compare_exchange_strong(mutex, &zero, 1)) return; /* Yes */

        while(1) {
            /* Futex is not available; mark contended and wait. */
            if (atomic_load(mutex) == 2 || atomic_compare_exchange_strong(mutex, &one, 2)) {
                s = futex(mutex, FUTEX_WAIT_PRIVATE, 2, NULL, NULL, 0);
                assert(s != -1 || errno == EAGAIN);
            }

            if (atomic_compare_exchange_strong(mutex, &zero, 2)) {
                return;
            }
        }
    }
}


void sys_mutex_unlock(sys_mutex_t  *mutex)
{
    long s;

    /* atomic_compare_exchange_strong() was described
       in comments above. */

    const uint32_t one = 1;
    if (atomic_compare_exchange_strong(mutex, &one, 0)) {
        return;  // uncontended case, nobody was waiting
    }
    atomic_store(mutex, 0);
    s = futex(mutex, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
    assert(s != -1);
}


struct sys_cond_t {
    pthread_cond_t cond;
};


void sys_cond(sys_cond_t* cond)
{
    atomic_init(cond, 0);
}


void sys_cond_free(sys_cond_t *cond)
{
    (void) cond;
}


void sys_cond_wait(sys_cond_t *cond, sys_mutex_t *held_mutex)
{
    sys_mutex_unlock(held_mutex);
    fwait(cond);  // can be simplified, do the atomic check first, only then drop lock
    sys_mutex_lock(held_mutex);
}


void sys_cond_signal(sys_cond_t *cond)
{
    fpost(cond);
}


void sys_cond_signal_all(sys_cond_t *cond)
{
    abort();
}


struct sys_rwlock_t {
    pthread_rwlock_t lock;
};


sys_rwlock_t *sys_rwlock(void)
{
    sys_rwlock_t *lock = NEW(sys_rwlock_t);
    pthread_rwlock_init(&(lock->lock), 0);
    return lock;
}


void sys_rwlock_free(sys_rwlock_t *lock)
{
    pthread_rwlock_destroy(&(lock->lock));
    free(lock);
}


void sys_rwlock_wrlock(sys_rwlock_t *lock)
{
    int result = pthread_rwlock_wrlock(&(lock->lock));
    assert(result == 0);
}


void sys_rwlock_rdlock(sys_rwlock_t *lock)
{
    int result = pthread_rwlock_rdlock(&(lock->lock));
    assert(result == 0);
}


void sys_rwlock_unlock(sys_rwlock_t *lock)
{
    int result = pthread_rwlock_unlock(&(lock->lock));
    assert(result == 0);
}


struct sys_thread_t {
    pthread_t thread;
    void *(*f)(void *);
    void *arg;
};

// initialize the per-thread _self to a non-zero value.  This dummy value will
// be returned when sys_thread_self() is called from the process's main thread
// of execution (which is not a pthread).  Using a non-zero value provides a
// way to distinguish a thread id from a zero (unset) value.
//
static sys_thread_t  _main_thread_id;
static __thread sys_thread_t *_self = &_main_thread_id;


// bootstrap _self before calling thread's main function
//
static void *_thread_init(void *arg)
{
    _self = (sys_thread_t*) arg;
    return _self->f(_self->arg);
}


sys_thread_t *sys_thread(void *(*run_function) (void *), void *arg)
{
    sys_thread_t *thread = NEW(sys_thread_t);
    thread->f = run_function;
    thread->arg = arg;
    pthread_create(&(thread->thread), 0, _thread_init, (void*) thread);
    return thread;
}


sys_thread_t *sys_thread_self()
{
    return _self;
}


void sys_thread_free(sys_thread_t *thread)
{
    assert(thread != &_main_thread_id);
    free(thread);
}


void sys_thread_join(sys_thread_t *thread)
{
    assert(thread != &_main_thread_id);
    pthread_join(thread->thread, 0);
}
