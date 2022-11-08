#define _GNU_SOURCE

#include "file.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <math.h>
#include "allocator.h"
#include "debug.h"
#include "file_hash.h"
#include "libnvmmio.h"
#include "lock.h"

extern struct timeval tv_begin[],tv_end[];
extern long long call_number[];
extern long long runtime_us[];

struct fops_struct posix;
file_t *fd_table[MAX_FD] = {
    0,
};

volatile bool initialized = false;

static void libnvmmio_open(int fd, int flags, int mode) {
  struct stat statbuf;
  file_t *file;
  mmio_t *mmio;
  unsigned long fsize;
  unsigned long ino;
  int s;
  if (__glibc_unlikely(posix.__fxstat == NULL)) {
    posix.__fxstat = dlsym(RTLD_NEXT, "__fxstat");
    if (__glibc_unlikely(posix.__fxstat == NULL)) {
      HANDLE_ERROR("dlsym(__fxstat)");
    }
  }

  s = posix.__fxstat(_STAT_VER, fd, &statbuf);
  if (__glibc_unlikely(s != 0)) {
    HANDLE_ERROR("fstat");
  }

  ino = statbuf.st_ino;
  fsize = statbuf.st_size;

  PRINT("fd = %d ino = %d fsize = %d",fd, ino, fsize);
  
  mmio = get_mmio_hash(ino);
  if (mmio == NULL) {
    PRINT("fd = %d ino = %ld fsize = %ld",fd, ino, fsize);
    mmio = get_new_mmio(fd, flags, ino, fsize);
    mmio = put_mmio_hash(ino, mmio);
    if (mmio->ref > 1) mmio->policy_l = FINELOCK;
    FLUSH(mmio,sizeof(mmio_t));
    FENCE();
  }
  PRINT("fd = %d mmio->fsize = %d",fd, mmio->fsize);
  file = (file_t *)malloc(sizeof(file_t));
  if (__glibc_unlikely(file == NULL)) {
    HANDLE_ERROR("malloc");
  }

  file->flags = flags;
  file->mode = mode;
  file->mmio = mmio;
  file->ino = ino;
  file->pos = 0;
  file->tid = (unsigned long)gettid();
  pthread_mutex_init(&file->mutex, NULL);

  PRINT("fd = %d",fd);
  fd_table[fd] = file;
}

void init_fops(void) {
  posix.open = dlsym(RTLD_NEXT, "open");
  if (__glibc_unlikely(posix.open == NULL)) {
    HANDLE_ERROR("dlsym(open)");
  }

  posix.open64 = dlsym(RTLD_NEXT, "open64");
  if (__glibc_unlikely(posix.open64 == NULL)) {
    HANDLE_ERROR("dlsym(open64)");
  }

  posix.read = dlsym(RTLD_NEXT, "read");
  if (__glibc_unlikely(posix.read == NULL)) {
    HANDLE_ERROR("dlsym(read)");
  }

  posix.write = dlsym(RTLD_NEXT, "write");
  if (__glibc_unlikely(posix.write == NULL)) {
    HANDLE_ERROR("dlsym(write)");
  }

  posix.pread = dlsym(RTLD_NEXT, "pread");
  if (__glibc_unlikely(posix.pread == NULL)) {
    HANDLE_ERROR("dlsym(pread)");
  }

  posix.pwrite = dlsym(RTLD_NEXT, "pwrite");
  if (__glibc_unlikely(posix.pwrite == NULL)) {
    HANDLE_ERROR("dlsym(pwrite)");
  }

  posix.pread64 = dlsym(RTLD_NEXT, "pread64");
  if (__glibc_unlikely(posix.pread64 == NULL)) {
    HANDLE_ERROR("dlsym(pread64)");
  }

  posix.pwrite64 = dlsym(RTLD_NEXT, "pwrite64");
  if (__glibc_unlikely(posix.pwrite64 == NULL)) {
    HANDLE_ERROR("dlsym(pwrite64)");
  }

  posix.fsync = dlsym(RTLD_NEXT, "fsync");
  if (__glibc_unlikely(posix.fsync == NULL)) {
    HANDLE_ERROR("dlsym(fsync)");
  }

  posix.fdatasync = dlsym(RTLD_NEXT, "fdatasync");
  if (__glibc_unlikely(posix.fdatasync == NULL)) {
    HANDLE_ERROR("dlsym(fdatasync)");
  }

  posix.lseek = dlsym(RTLD_NEXT, "lseek");
  if (__glibc_unlikely(posix.lseek == NULL)) {
    HANDLE_ERROR("dlsym(lseek)");
  }

  posix.truncate = dlsym(RTLD_NEXT, "truncate");
  if (__glibc_unlikely(posix.truncate == NULL)) {
    HANDLE_ERROR("dlsym(truncate)");
  }

  posix.ftruncate = dlsym(RTLD_NEXT, "ftruncate");
  if (__glibc_unlikely(posix.ftruncate == NULL)) {
    HANDLE_ERROR("dlsym(ftruncate)");
  }

  posix.ftruncate64 = dlsym(RTLD_NEXT, "ftruncate64");
  if (__glibc_unlikely(posix.ftruncate64 == NULL)) {
    HANDLE_ERROR("dlsym(ftruncate64)");
  }

  posix.stat = dlsym(RTLD_NEXT, "__xstat64");
  if (__glibc_unlikely(posix.stat == NULL)) {
    HANDLE_ERROR("dlsym(stat)");
  }

  posix.__fxstat = dlsym(RTLD_NEXT, "__fxstat");
  if (__glibc_unlikely(posix.__fxstat == NULL)) {
    HANDLE_ERROR("dlsym(__fxstat)");
  }

  posix.__fxstat64 = dlsym(RTLD_NEXT, "__fxstat64");
  if (__glibc_unlikely(posix.__fxstat64 == NULL)) {
    HANDLE_ERROR("dlsym(__fxstat64)");
  }

  posix.close = dlsym(RTLD_NEXT, "close");
  if (__glibc_unlikely(posix.close == NULL)) {
    HANDLE_ERROR("dlsym(close)");
  }
}

static inline file_t *get_file(int fd) { return fd_table[fd]; }

int open(const char *pathname, int flags, ...) {
  int fd, mode = 0;
  if (flags & O_CREAT) {
    va_list arg;
    va_start(arg, flags);
    mode = va_arg(arg, int);
    va_end(arg);
  }

  if (__glibc_unlikely(posix.open == NULL)) {
    posix.open = dlsym(RTLD_NEXT, "open");
    if (__glibc_unlikely(posix.open == NULL)) {
      HANDLE_ERROR("dlsym(open)");
    }
  }


  fd = posix.open(pathname, flags, mode);  
  if (flags & O_ATOMIC) {
    PRINT("open pathname=%s, flags=%d, fd=%d tid = %d atomic = %d", pathname, flags, fd, gettid(), flags & O_ATOMIC);
    libnvmmio_open(fd, flags, mode);
  }
  return fd;
}

int open64(const char *pathname, int flags, ...) {
  int fd, mode = 0;
  if (flags & O_CREAT) {
    va_list arg;
    va_start(arg, flags);
    mode = va_arg(arg, int);
    va_end(arg);
  }

  if (__glibc_unlikely(posix.open64 == NULL)) {
    posix.open64 = dlsym(RTLD_NEXT, "open64");
    if (__glibc_unlikely(posix.open64 == NULL)) {
      HANDLE_ERROR("dlsym(open64)");
    }
  }
  fd = posix.open64(pathname, flags, mode);
  PRINT("open64 pathname=%s, flags=%d, fd=%d\n", pathname, flags, fd);
    
  if (flags & O_ATOMIC) {
    PRINT("open64 pathname=%s, flags=%d, fd=%d tid = %d atomic = %d\n", pathname, flags, fd, gettid(), flags & O_ATOMIC);
    libnvmmio_open(fd, flags, mode);
  }
  return fd;
}

ssize_t read(int fd, void *buf, size_t len) {
  file_t *file;
  int ret;
  file = get_file(fd);

  if (__glibc_likely(file != NULL)) {
    MUTEX_LOCK(&file->mutex);
    PRINT("read fd=%d, pos = %lu, len=%lu\n", fd, file->pos,len);
    ret = mmio_read_mgl(file->mmio, fd, file->pos, buf, len);
    file->pos += ret;
    PRINT("read end fd=%d, pos = %lu, len=%lu\n", fd, file->pos,len);
    MUTEX_UNLOCK(&file->mutex);

    return ret;
  }

  if (__glibc_unlikely(posix.read == NULL)) {
    posix.read = dlsym(RTLD_NEXT, "read");
    if (__glibc_unlikely(posix.read == NULL)) {
      HANDLE_ERROR("dlsym(read)");
    }
  }

  return posix.read(fd, buf, len);
}

ssize_t write(int fd, const void *buf, size_t len) {
  //call_number[0]++;
  //gettimeofday(&tv_begin[0], NULL);
  file_t *file;
  int ret;
  file = get_file(fd);
  if (__glibc_likely(file != NULL)) {
    MUTEX_LOCK(&file->mutex);    
    PRINT("write fd=%d, pos = %u len=%lu tid = %d\n", fd, file->pos,len,fd_table[fd]->tid);
    ret = mmio_write_mgl(file->mmio, fd, file->pos, buf, len, fd_table[fd]->tid);
    //gettimeofday(&tv_end[1], NULL);
    //runtime_us[1]+=((tv_end[1].tv_sec - tv_begin[1].tv_sec) * 1000000 + tv_end[1].tv_usec - tv_begin[1].tv_usec);
    file->pos += ret;    
    MUTEX_UNLOCK(&file->mutex);    
    //gettimeofday(&tv_end[0], NULL);
    //runtime_us[0]+=((tv_end[0].tv_sec - tv_begin[0].tv_sec) * 1000000 + tv_end[0].tv_usec - tv_begin[0].tv_usec);
    PRINT("endwrite fd = %d tid = %d\n", fd, fd_table[fd]->tid);
    return ret;
  }

  if (__glibc_unlikely(posix.write == NULL)) {
    posix.write = dlsym(RTLD_NEXT, "write");
    if (__glibc_unlikely(posix.write == NULL)) {
      HANDLE_ERROR("dlsym(write)");
    }
  }

  return posix.write(fd, buf, len);
}

ssize_t pread64(int fd, void *buf, size_t count, off_t pos) {
  PRINT("pread64 fd=%d, pos = %lu, len=%lu\n", fd, pos,count);
  PRINT("call");

  file_t *file;
  int ret;
  file = get_file(fd);

  if (__glibc_likely(file != NULL)) {
    MUTEX_LOCK(&file->mutex);
    PRINT("pread64 fd=%d, pos = %lu, len=%lu\n", fd, pos,count);
    ret = mmio_read_mgl(file->mmio, fd, pos, buf, count);
    MUTEX_UNLOCK(&file->mutex);

    return ret;
  }

  if (__glibc_unlikely(posix.pread64 == NULL)) {
    posix.pread64 = dlsym(RTLD_NEXT, "pread64");
    if (__glibc_unlikely(posix.pread64 == NULL)) {
      HANDLE_ERROR("dlsym(pread)");
    }
  }

  return posix.pread64(fd, buf, count, pos);
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off_t pos) {
  PRINT("pwrite64 fd=%d, pos = %u len=%lu\n", fd, pos,count);
  PRINT("call");

  file_t *file;
  int ret;

  file = get_file(fd);

  if (__glibc_likely(file != NULL)) {
    MUTEX_LOCK(&file->mutex);    
    ret = mmio_write_mgl(file->mmio, fd, pos, buf, count, fd_table[fd]->tid);
    MUTEX_UNLOCK(&file->mutex);    
    return ret;
  }

  if (__glibc_unlikely(posix.pwrite64 == NULL)) {
    posix.pwrite64 = dlsym(RTLD_NEXT, "pwrite64");
    if (__glibc_unlikely(posix.pwrite64 == NULL)) {
      HANDLE_ERROR("dlsym(pwrite64)");
    }
  }
  return posix.pwrite64(fd, buf, count, pos);
}

ssize_t pread(int fd, void *buf, size_t count, off_t pos) {
  PRINT("pread fd=%d, pos = %u len=%lu\n", fd, pos,count);
  PRINT("call");

  file_t *file;
  int ret;
  file = get_file(fd);

  if (__glibc_likely(file != NULL)) {
    MUTEX_LOCK(&file->mutex);
    ret = mmio_read_mgl(file->mmio, fd, pos, buf, count);
    MUTEX_UNLOCK(&file->mutex);

    return ret;
  }

  if (__glibc_unlikely(posix.pread == NULL)) {
    posix.pread = dlsym(RTLD_NEXT, "pread");
    if (__glibc_unlikely(posix.pread == NULL)) {
      HANDLE_ERROR("dlsym(pread)");
    }
  }

  return posix.pread(fd, buf, count, pos);
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t pos) {
  PRINT("pwrite fd=%d, pos = %u len=%lu\n", fd, pos,count);
  PRINT("call");

  file_t *file;
  int ret;

  file = get_file(fd);

  if (__glibc_likely(file != NULL)) {
    MUTEX_LOCK(&file->mutex);    
    ret = mmio_write_mgl(file->mmio, fd, pos, buf, count, fd_table[fd]->tid);
    MUTEX_UNLOCK(&file->mutex);    
    return ret;
  }

  if (__glibc_unlikely(posix.pwrite == NULL)) {
    posix.pwrite = dlsym(RTLD_NEXT, "pwrite");
    if (__glibc_unlikely(posix.pwrite == NULL)) {
      HANDLE_ERROR("dlsym(pwrite)");
    }
  }
  return posix.pwrite(fd, buf, count, pos);
}

int fsync(int fd) {
  file_t *file;

  PRINT("fsync fd=%d", fd);
  file = get_file(fd);
  if (file != NULL) {
    PRINT("fsync fd=%d", fd);
    return 0;
  }

  if (__glibc_unlikely(posix.fsync == NULL)) {
    posix.fsync = dlsym(RTLD_NEXT, "fsync");
    if (__glibc_unlikely(posix.fsync == NULL)) {
      HANDLE_ERROR("dlsym(fsync)");
    }
  }

  return posix.fsync(fd);
}

int fdatasync(int fd){
  file_t *file;

  file = get_file(fd);
  if (file != NULL) {
    PRINT("fdatasync fd=%d\n", fd);
    PRINT("mmio = %p mmio->start = %p mmio->ino = %d mmio->offset = %d", file->mmio, file->mmio->start, file->mmio->ino, file->mmio->offset);
    PRINT("file=%p file_size = %d", file, file->mmio->fsize);
    return 0;
  }

  if (__glibc_unlikely(posix.fdatasync == NULL)) {
    posix.fdatasync = dlsym(RTLD_NEXT, "fdatasync");
    if (__glibc_unlikely(posix.fdatasync == NULL)) {
      HANDLE_ERROR("dlsym(fsync)");
    }
  }

  return posix.fdatasync(fd);
}

off_t lseek(int fd, off_t offset, int whence) {
  file_t *file;
  off_t ret;
  off_t fsize;

  PRINT("lseek fd=%d, offset=%ld, whence=%d", fd, offset, whence);

  file = get_file(fd);
  if (file != NULL) {
    PRINT("mmio = %p mmio->start = %p mmio->ino = %d mmio->offset = %d", file->mmio, file->mmio->start, file->mmio->ino, file->mmio->offset);
    MUTEX_LOCK(&file->mutex);
    fsize = file->mmio->fsize;

    switch (whence) {
      case SEEK_SET:
        if (offset > fsize) {
          PRINT(
              "The requested offset exceeds the file size: filesize=%lu, "
              "offset=%lu",
              fsize, offset);
        }
        file->pos = offset;
        ret = offset;
        break;
      case SEEK_CUR:
        if (file->pos + offset > fsize) {
          HANDLE_ERROR(
              "The requested offset exceeds the file size: filesize=%lu, "
              "offset=%lu",
              fsize, file->pos + offset);
        }
        file->pos += offset;
        ret = file->pos;
        break;
      case SEEK_END:
        if (fsize + offset > fsize) {
          HANDLE_ERROR(
              "The requested offset exceeds the file size: filesize=%lu, "
              "offset=%lu",
              fsize, fsize + offset);
        }
        file->pos = fsize + offset;
        break;
      default:
        HANDLE_ERROR("wrong whence");
        break;
    }
    ret = file->pos;

    MUTEX_UNLOCK(&file->mutex);
    return ret;
  }

  if (__glibc_unlikely(posix.lseek == NULL)) {
    posix.lseek = dlsym(RTLD_NEXT, "lseek");
    if (__glibc_unlikely(posix.lseek == NULL)) {
      HANDLE_ERROR("dlsym(lseek)");
    }
  }

  return posix.lseek(fd, offset, whence);
}

off64_t lseek64(int fd, off64_t offset, int whence) {
  PRINT("call");
  return (off64_t)lseek(fd, (off_t)offset, whence);
}

int truncate(const char *path, off_t length) {
  PRINT("call");

  if (__glibc_unlikely(posix.truncate == NULL)) {
    posix.truncate = dlsym(RTLD_NEXT, "truncate");
    if (__glibc_unlikely(posix.truncate == NULL)) {
      HANDLE_ERROR("dlsym(truncate)");
    }
  }

  return posix.truncate(path, length);
}

int ftruncate(int fd, off_t length) {
  PRINT("ftruncate fd = %d length = %d\n",fd,length);
  file_t *file;
  file = get_file(fd);
  if (file != NULL) {
    MUTEX_LOCK(&file->mutex);
    PRINT("length = %d\n",length);
    file->mmio->fsize = length;
    MUTEX_UNLOCK(&file->mutex);
  }
  if (__glibc_unlikely(posix.ftruncate == NULL)) {
    posix.ftruncate = dlsym(RTLD_NEXT, "ftruncate");
    if (__glibc_unlikely(posix.ftruncate == NULL)) {
      HANDLE_ERROR("dlsym(ftruncate)");
    }
  }

  PRINT("ftruncate fd = %d length = %d\n",fd,length);
  return posix.ftruncate(fd, length);
}

int ftruncate64(int fd, off_t length) {
  PRINT("ftruncate64 fd = %d length = %d\n",fd,length);
  file_t *file;
  file = get_file(fd);
  if (file != NULL) {
    MUTEX_LOCK(&file->mutex);
    PRINT("file size = %d\n", length);
    file->mmio->fsize = length;
    file->mmio->end = file->mmio->start + length;
    PRINT("mmio = %p file size = %d\n", file->mmio, length);
    MUTEX_UNLOCK(&file->mutex);
  }
  if (__glibc_unlikely(posix.ftruncate == NULL)) {
    posix.ftruncate = dlsym(RTLD_NEXT, "ftruncate64");
    if (__glibc_unlikely(posix.ftruncate64 == NULL)) {
      HANDLE_ERROR("dlsym(ftruncate64)");
    }
  }

  int ret = posix.ftruncate(fd, length);
  PRINT("ftruncate64 fd = %d length = %d, ret = %d errno = %d\n",fd,length,ret,errno);
  return ret;
}

int stat(const char *pathname, struct stat *statbuf) {
  printf("call stat\n");

  if (__glibc_unlikely(posix.stat == NULL)) {
    posix.stat = dlsym(RTLD_NEXT, "__xstat64");
    if (__glibc_unlikely(posix.stat == NULL)) {
      HANDLE_ERROR("dlsym(stat)");
    }
  }

  return posix.stat(pathname, statbuf);
}

int __fxstat(int var, int fd, struct stat *statbuf) {
  PRINT("call fstat\n");

  if (__glibc_unlikely(posix.__fxstat == NULL)) {
    posix.__fxstat = dlsym(RTLD_NEXT, "__fxstat");
    if (__glibc_unlikely(posix.__fxstat == NULL)) {
      HANDLE_ERROR("dlsym(__fxstat)");
    }
  }
  int ret = posix.__fxstat(var, fd, statbuf);
  // modify the file size of statbuf
  PRINT("file size = %lu\n",statbuf->st_size);
  file_t *file;
  if (fd_table[fd] != NULL) {
    file = fd_table[fd];
    MUTEX_LOCK(&file->mutex);
    statbuf->st_size = file->mmio->fsize;
    MUTEX_UNLOCK(&file->mutex);
  }
  PRINT("file size = %lu\n",statbuf->st_size);
  return ret;
}

int __fxstat64(int var, int fd, struct stat64 *statbuf) {
  PRINT("call fstat64\n");

  if (__glibc_unlikely(posix.__fxstat64 == NULL)) {
    posix.__fxstat64 = dlsym(RTLD_NEXT, "__fxstat64");
    if (__glibc_unlikely(posix.__fxstat64 == NULL)) {
      HANDLE_ERROR("dlsym(__fxstat64)");
    }
  }
  int ret = posix.__fxstat64(var, fd, statbuf);
  // modify the file size of statbuf
  PRINT("fd = %d file size = %lu\n",fd, statbuf->st_size);
  file_t *file;
  if (fd_table[fd] != NULL) {
    file = fd_table[fd];
    MUTEX_LOCK(&file->mutex);
    statbuf->st_size = file->mmio->fsize;
    MUTEX_UNLOCK(&file->mutex);
  }
  PRINT("fd =  %d file size = %lu\n",fd, statbuf->st_size);
  return ret;
}

int close(int fd) {
  file_t *file;

  PRINT("tid = %d close fd = %d", gettid(),fd);
  if (fd_table[fd] != NULL) {
    PRINT("close fd = %d", fd);
    file = fd_table[fd];
    MUTEX_LOCK(&file->mutex);
    delete_mmio_hash(fd, file);
    MUTEX_UNLOCK(&file->mutex);
    PRINT("Free file fd = %d", fd);
    free(file);
    
    fd_table[fd] = NULL;
    PRINT("release the file sturcut");
  }

  if (__glibc_unlikely(posix.close == NULL)) {
    posix.close = dlsym(RTLD_NEXT, "close");
    if (__glibc_unlikely(posix.close == NULL)) {
      HANDLE_ERROR("dlsym(close)");
    }
  }

  return posix.close(fd);
}

static void init_libnvmmio(void) {
  init_fops();
  init_allocator();
  init_file_hash();
}

void __attribute__((constructor)) load_libnvmmio(void) {
  if (__sync_bool_compare_and_swap(&initialized, false, true)) {
    PRINT("tid = %d initialized = %d", gettid(), initialized);
    init_libnvmmio();
    PRINT("initialized Libnvmmio");
  }
}
