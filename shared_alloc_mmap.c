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

#if defined(MAP_ANON) && !defined(MAP_ANONYMOUS)
# define MAP_ANONYMOUS MAP_ANON
#endif

static int create_segments(size_t requested_size, zend_shared_segment ***shared_segments_p, int *shared_segments_count, char **error_in)
{
	zend_shared_segment *shared_segment;
    int fd=-1;
    int ret=ALLOC_FAILURE;
    char file[MAXPATHLEN];
    pthread_mutexattr_t* attr;
    int result;

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
        if(ftruncate(fd, requested_size) < 0) {
            close(fd);
            unlink(file);
            return ret;
         }
     ret=FILE_REATTACHED;
    }else{
        fd = open(file , O_RDWR|O_CREAT, S_IRUSR | S_IWUSR);
        if(fd != -1) {
            if(ftruncate(fd, requested_size) < 0) {
                close(fd);
                unlink(file);
                return ret;
            }
        ret=ALLOC_SUCCESS;
        }
    }
    
    shared_segment->p = (void *) mmap( MMAP_ADDR, requested_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_NOSYNC|MAP_FIXED, fd, 0);

    if (shared_segment->p == MAP_FAILED) {
            *error_in = "mmap";
            return ALLOC_FAILURE;
    }

	shared_segment->pos = sizeof(magick_shared_globals) + sizeof(pthread_mutex_t);
	shared_segment->size = requested_size;
    shared_globals_helper = shared_segment->p;

    if(ret!=FILE_REATTACHED) {
        zend_accel_error(ACCEL_LOG_DEBUG, "Lock created"); 
        shared_globals_helper->shared_mutex = shared_segment->p + sizeof(magick_shared_globals);

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

        efree(attr);
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
