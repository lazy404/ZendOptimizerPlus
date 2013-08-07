/*
   +----------------------------------------------------------------------+
   | Zend OPcache                                                         |
   +----------------------------------------------------------------------+
   | Copyright (c) 1998-2013 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Authors: Andi Gutmans <andi@zend.com>                                |
   |          Zeev Suraski <zeev@zend.com>                                |
   |          Stanislav Malyshev <stas@zend.com>                          |
   |          Dmitry Stogov <dmitry@zend.com>                             |
   +----------------------------------------------------------------------+
*/

#include "zend_shared_alloc.h"

#ifdef USE_MMAP

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <pthread.h>

#define _BSD_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#ifndef MAP_NOSYNC
#define MAP_NOSYNC 0
#endif

/* MAXPATHLEN */
#include <unistd.h>
#include <signal.h>

#if defined(MAP_ANON) && !defined(MAP_ANONYMOUS)
# define MAP_ANONYMOUS MAP_ANON
#endif


static void remove_cache_file(int signo, siginfo_t *siginfo, void *context) 
{
    if( ZSMMG(shared_segments_count) != 0) {
        fprintf(stderr, "zop emergency cache delete %d %s\n", getpid(), ZSMMG(shared_segments)[0]->filename);
        unlink(ZSMMG(shared_segments)[0]->filename);
        ZSMMG(shared_segments_count)=0;
    }
    exit(1);
}


static int create_segments(size_t requested_size, zend_shared_segment ***shared_segments_p, int *shared_segments_count, char **error_in)
{
	zend_shared_segment *shared_segment;
    int fd=-1;
    int ret=ALLOC_FAILURE;
    char file[MAXPATHLEN];
    pthread_mutexattr_t* attr;
    pthread_rwlockattr_t* rwattr;
    int result;
    struct sigaction sa = {{0}};

    requested_size += sizeof(magick_shared_globals) + sizeof(pthread_mutex_t);

    snprintf(file, MAXPATHLEN-1, "%s%d", ZCG(accel_directives).mmap_prefix, getuid());
    *shared_segments_count = 1;
    *shared_segments_p = (zend_shared_segment **) calloc(1, sizeof(zend_shared_segment) + sizeof(void *));
    if (!*shared_segments_p) {
            *error_in = "calloc";
            return ALLOC_FAILURE;
    }
    shared_segment = (zend_shared_segment *)((char *)(*shared_segments_p) + sizeof(void *));
    (*shared_segments_p)[0] = shared_segment;

    fd = open(file , O_RDWR, S_IRUSR | S_IWUSR);
    if(fd != -1) {
        if(ftruncate(fd, requested_size+4096) < 0) {
            close(fd);
            unlink(file);
            return ret;
         }
     ret=FILE_REATTACHED;
    }else{
        fd = open(file , O_RDWR|O_CREAT, S_IRUSR | S_IWUSR);
        if(fd != -1) {
            if(ftruncate(fd, requested_size+4096) < 0) {
                close(fd);
                unlink(file);
                return ret;
            }
        ret=ALLOC_SUCCESS;
        }
    }

    shared_segment->p = (void *) mmap( MMAP_ADDR, requested_size+4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_NOSYNC|MAP_FIXED, fd, 0);

    shared_segment->filename=calloc(strlen(file)+1,sizeof(char));
    strcpy(shared_segment->filename, file);

    if (shared_segment->p == MAP_FAILED) {
            *error_in = "mmap";
            return ALLOC_FAILURE;
    }

    sa.sa_sigaction=&remove_cache_file;
    sa.sa_flags = SA_SIGINFO;

    if (sigaction(SIGBUS, &sa, NULL) != 0) {
            *error_in = "mmap.3";
            return ALLOC_FAILURE;
    }

    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
            *error_in = "mmap.4";
            return ALLOC_FAILURE;
    }
    if (sigaction(SIGFPE, &sa, NULL) != 0) {
            *error_in = "mmap.5";
            return ALLOC_FAILURE;
    }

	shared_segment->pos = 0;
	shared_segment->size = requested_size;
    shared_globals_helper = shared_segment->p+requested_size;

    if(ret!=FILE_REATTACHED) {
        zend_accel_error(ACCEL_LOG_DEBUG, "Lock created"); 
        shared_globals_helper->shared_mutex = shared_segment->p + requested_size +  sizeof(magick_shared_globals);
        shared_globals_helper->restart_mutex = shared_globals_helper->shared_mutex + sizeof(pthread_mutex_t);
        shared_globals_helper->mem_usage_rwlock = shared_globals_helper->restart_mutex + sizeof(pthread_mutex_t);

        attr = emalloc(sizeof(pthread_mutexattr_t));

        result = pthread_mutexattr_init(attr);
        if(result == ENOMEM) {
            *error_in = "mmap2";
            return ALLOC_FAILURE;
        } else if(result == EINVAL) {
            *error_in = "mmap3";
            return ALLOC_FAILURE;
        } else if(result == EFAULT) {
            *error_in = "mmap4";
            return ALLOC_FAILURE;
        }

        result = pthread_mutexattr_setpshared(attr, PTHREAD_PROCESS_SHARED);
        if(result == EINVAL) {
            *error_in = "mmap5";
            return ALLOC_FAILURE;
        } else if(result == EFAULT) {
            *error_in = "mmap6";
            return ALLOC_FAILURE;
        } else if(result == ENOTSUP) {
            *error_in = "mmap7";
            return ALLOC_FAILURE;
        }


        if(pthread_mutex_init(shared_globals_helper->shared_mutex, attr)) {
            efree(attr);
            *error_in = "mmap8";
            return ALLOC_FAILURE;
        }

        if(pthread_mutex_init(shared_globals_helper->restart_mutex, attr)) {
            efree(attr);
            *error_in = "mmap9";
            return ALLOC_FAILURE;
        }

        efree(attr);

        rwattr=emalloc(sizeof(pthread_rwlock_t));
        if(!rwattr) {
            *error_in="mmap9.1";
            return ALLOC_FAILURE;
        }

        result = pthread_rwlockattr_init(rwattr);
        if( result != 0 ) {
            *error_in="mmap9.2";
            efree(rwattr);
            return ALLOC_FAILURE;
        }

        result = pthread_rwlockattr_setpshared(rwattr, PTHREAD_PROCESS_SHARED);
        if( result != 0 ) {
            *error_in="mmap9.3";
            efree(rwattr);
            return ALLOC_FAILURE;
        }

        if(pthread_rwlock_init(shared_globals_helper->mem_usage_rwlock, rwattr)) { 
            *error_in="mmap10";
            efree(rwattr);
            return ALLOC_FAILURE;
        }

        pthread_rwlockattr_destroy(rwattr);
        efree(rwattr);
    }
	return ret;
}

static int detach_segment(zend_shared_segment *shared_segment)
{
	munmap(shared_segment->p, shared_segment->size);
	return 0;
}

static size_t segment_type_size(void)
{
	return sizeof(zend_shared_segment);
}

zend_shared_memory_handlers zend_alloc_mmap_handlers = {
	create_segments,
	detach_segment,
	segment_type_size
};

#endif /* USE_MMAP */
