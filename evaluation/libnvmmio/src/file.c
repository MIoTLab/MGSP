#define _GNU_SOURCE

#include "file.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>

#include "allocator.h"
#include "debug.h"
#include "file_hash.h"
#include "libnvmmio.h"
#include "lock.h"

struct fops_struct posix;
file_t *fd_table[MAX_FD] = {
    0,
};

bool initialized = false;

static void libnvmmio_open(int fd, int flags, int mode) {
  struct stat statbuf;
  file_t *file;
  mmio_t *mmio;
  unsigned long fsize;
  unsigned long ino;
  int s;

  PRINT("fd=%d, flags=%d, mode=%d", fd, flags, mode);

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

  mmio = get_mmio_hash(ino);

  if (mmio == NULL) {
    mmio = get_new_mmio(fd, flags, ino, fsize);
    mmio = put_mmio_hash(ino, mmio);
  }

  file = (file_t *)malloc(sizeof(file_t));
  if (__glibc_unlikely(file == NULL)) {
    HANDLE_ERROR("malloc");
  }

  file->flags = flags;
  file->mode = mode;
  file->mmio = mmio;
  file->ino = ino;
  file->pos = 0;
  pthread_mutex_init(&file->mutex, NULL);

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
  if (__glibc_unlikely(posix.ftruncate64== NULL)) {
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
  PRINT("pathname=%s, flags=%d, fd=%d", pathname, flags, fd);
  if (flags & O_ATOMIC) {
    PRINT("open pathname=%s, flags=%d, fd=%d atomic = %d", pathname, flags, fd, flags & O_ATOMIC);
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
  PRINT("pathname=%s, flags=%d, fd=%d", pathname, flags, fd);
  if (flags & O_ATOMIC) {
    PRINT("open64 pathname=%s, flags=%d, fd=%d atomic = %d", pathname, flags, fd, flags & O_ATOMIC);
    libnvmmio_open(fd, flags, mode);
  }
  return fd;
}

ssize_t read(int fd, void *buf, size_t len) {
  file_t *file;
  int ret;

  file = get_file(fd);

  if (__glibc_likely(file != NULL)) {
    PRINT("start read fd=%d, buf=%p, len=%lu\n", fd, buf, len);
    MUTEX_LOCK(&file->mutex);

    ret = mmio_read(file->mmio, file->pos, buf, len);
    file->pos += ret;

    MUTEX_UNLOCK(&file->mutex);

    PRINT("end read fd=%d, buf=%p, len=%lu\n", fd, buf, len);
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
  file_t *file;
  int ret;

  PRINT("write fd=%d, buf=%p, len=%lu\n", fd, buf, len);

  file = get_file(fd);

  if (__glibc_likely(file != NULL)) {
    MUTEX_LOCK(&file->mutex);

    PRINT("start write fd=%d, buf=%p, len=%lu\n", fd, buf, len);
    ret = mmio_write(file->mmio, fd, file->pos, buf, len);
    file->pos += ret;

    MUTEX_UNLOCK(&file->mutex);
    PRINT("end write fd=%d, buf=%p, len=%lu\n", fd, buf, len);
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

ssize_t pread(int fd, void *buf, size_t count, off_t pos) {
  PRINT("call");

  file_t *file;
  int ret;

  file = get_file(fd);

  if (__glibc_likely(file != NULL)) {
    PRINT("start pread fd=%d, buf=%p, len=%lu\n", fd, buf, count);
    MUTEX_LOCK(&file->mutex);

    ret = mmio_read(file->mmio, pos, buf, count);
    file->pos += ret;

    MUTEX_UNLOCK(&file->mutex);

    PRINT("end read fd=%d, buf=%p, len=%lu\n", fd, buf, count);
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
  PRINT("call");
  file_t *file;
  int ret;

  file = get_file(fd);

  if (__glibc_likely(file != NULL)) {
    MUTEX_LOCK(&file->mutex);

    PRINT("start pwrite fd=%d, buf=%p, len=%lu\n", fd, buf, count);
    ret = mmio_write(file->mmio, fd, pos, buf, count);
    file->pos += ret;

    MUTEX_UNLOCK(&file->mutex);
    PRINT("end write fd=%d, buf=%p, len=%lu\n", fd, buf, count);
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

ssize_t pread64(int fd, void *buf, size_t count, off_t pos) {
  PRINT("call");

  file_t *file;
  int ret;

  file = get_file(fd);

  if (__glibc_likely(file != NULL)) {
    PRINT("start pread fd=%d, buf=%p, len=%lu\n", fd, buf, count);
    MUTEX_LOCK(&file->mutex);

    ret = mmio_read(file->mmio, pos, buf, count);
    file->pos += ret;

    MUTEX_UNLOCK(&file->mutex);

    PRINT("end read fd=%d, buf=%p, len=%lu\n", fd, buf, count);
    return ret;
  }

  if (__glibc_unlikely(posix.pread64 == NULL)) {
    posix.pread64 = dlsym(RTLD_NEXT, "pread64");
    if (__glibc_unlikely(posix.pread64 == NULL)) {
      HANDLE_ERROR("dlsym(pread64)");
    }
  }

  return posix.pread64(fd, buf, count, pos);
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off_t pos) {
  PRINT("call");
  file_t *file;
  int ret;

  file = get_file(fd);

  if (__glibc_likely(file != NULL)) {
    MUTEX_LOCK(&file->mutex);

    PRINT("start pwrite fd=%d, buf=%p, len=%lu\n", fd, buf, count);
    ret = mmio_write(file->mmio, fd, pos, buf, count);
    file->pos += ret;

    MUTEX_UNLOCK(&file->mutex);
    PRINT("end write fd=%d, buf=%p, len=%lu\n", fd, buf, count);
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

int fsync(int fd) {
  file_t *file;

  PRINT("fd=%d", fd);

  file = get_file(fd);
  if (file != NULL) {
    PRINT("fsync\n");
    MUTEX_LOCK(&file->mutex);
    commit_mmio(file->mmio);
    MUTEX_UNLOCK(&file->mutex);
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

int fdatasync(int fd) {
  file_t *file;

  PRINT("fd=%d", fd);

  file = get_file(fd);
  if (file != NULL) {
    MUTEX_LOCK(&file->mutex);
    PRINT("fdatasync fd=%d\n", fd);
    commit_mmio(file->mmio);
    MUTEX_UNLOCK(&file->mutex);
    return 0;
  }

  if (__glibc_unlikely(posix.fdatasync == NULL)) {
    posix.fdatasync = dlsym(RTLD_NEXT, "fdatasync");
    if (__glibc_unlikely(posix.fdatasync == NULL)) {
      HANDLE_ERROR("dlsym(fdatasync)");
    }
  }

  return posix.fdatasync(fd);
}

off_t lseek(int fd, off_t offset, int whence) {
  file_t *file;
  off_t ret;
  off_t fsize;

  PRINT("fd=%d, offset=%ld, whence=%d", fd, offset, whence);

  file = get_file(fd);
  if (file != NULL) {

    MUTEX_LOCK(&file->mutex);
    fsize = file->mmio->fsize;

    switch (whence) {
      case SEEK_SET:
        if (offset > fsize) {
          HANDLE_ERROR(
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
  PRINT("call\n");
  file_t *file;
  file = get_file(fd);
  if (file != NULL) {
    MUTEX_LOCK(&file->mutex);
    file->mmio->fsize = length;
    MUTEX_UNLOCK(&file->mutex);
  }
  if (__glibc_unlikely(posix.ftruncate == NULL)) {
    posix.ftruncate = dlsym(RTLD_NEXT, "ftruncate");
    if (__glibc_unlikely(posix.ftruncate == NULL)) {
      HANDLE_ERROR("dlsym(ftruncate)");
    }
  }

  return posix.ftruncate(fd, length);
}

int ftruncate64(int fd, off_t length) {
  PRINT("call\n");
  file_t *file;
  file = get_file(fd);
  if (file != NULL) {
    MUTEX_LOCK(&file->mutex);
    file->mmio->fsize = length;
    MUTEX_UNLOCK(&file->mutex);
  }
  if (__glibc_unlikely(posix.ftruncate64 == NULL)) {
    posix.ftruncate64 = dlsym(RTLD_NEXT, "ftruncate64");
    if (__glibc_unlikely(posix.ftruncate64 == NULL)) {
      HANDLE_ERROR("dlsym(ftruncate64)");
    }
  }

  return posix.ftruncate64(fd, length);
}

int stat(const char *pathname, struct stat *statbuf) {
  PRINT("call");

  if (__glibc_unlikely(posix.stat == NULL)) {
    posix.stat = dlsym(RTLD_NEXT, "__xstat64");
    if (__glibc_unlikely(posix.stat == NULL)) {
      HANDLE_ERROR("dlsym(stat)");
    }
  }

  return posix.stat(pathname, statbuf);
}

int fstat(int fd, struct stat *statbuf) {
  PRINT("call");

  if (__glibc_unlikely(posix.__fxstat == NULL)) {
    posix.__fxstat = dlsym(RTLD_NEXT, "__fxstat");
    if (__glibc_unlikely(posix.__fxstat == NULL)) {
      HANDLE_ERROR("dlsym(__fxstat)");
    }
  }

  return posix.__fxstat(_STAT_VER, fd, statbuf);
}

int __fxstat(int var, int fd, struct stat *statbuf) {
  PRINT("call fstat\n");

  if (__glibc_unlikely(posix.__fxstat == NULL)) {
    posix.__fxstat = dlsym(RTLD_NEXT, "__fxstat");
    if (__glibc_unlikely(posix.__fxstat == NULL)) {
      HANDLE_ERROR("dlsym(__fxstat)");
    }
  }
  int ret = posix.__fxstat(_STAT_VER, fd, statbuf);
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
  int ret = posix.__fxstat64(_STAT_VER, fd, statbuf);
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

int close(int fd) {
  file_t *file;

  PRINT("fd=%d", fd);

  if (fd_table[fd] != NULL) {
    PRINT("close fd=%d\n", fd);
    file = fd_table[fd];
    MUTEX_LOCK(&file->mutex);
    delete_mmio_hash(fd, file);
    MUTEX_UNLOCK(&file->mutex);
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
    init_libnvmmio();
    PRINT("initialized Libnvmmio");
  }
}
