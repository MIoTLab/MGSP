#ifndef LIBNVMMIO_MMAP_H
#define LIBNVMMIO_MMAP_H

#include <libpmem.h>
#include <pthread.h>

#include "radixlog.h"
#include "slist.h"
#include "bravo.h"

typedef enum { UNDO, REDO } policy_t;
typedef enum { READOPT, WRITEOPT } policy_g_t;
typedef enum { FILELOCK, FINELOCK } policy_l_t;

typedef struct mmio_struct {
  bravo_rwlock_t rwlock;
  uint8_t lock;
  void *start;
  void *end;
  unsigned long ino;
  unsigned long offset;
  unsigned long epoch;
  policy_t policy;
  policy_g_t policy_g;
  policy_l_t policy_l;
  radix_root_t radixlog;
  bitmap_log_t bitmaplog;
  unsigned long read;
  unsigned long write;
  unsigned long read_size;
  unsigned long write_size;
  off_t fsize;
  int ref;
} mmio_t;

void ntstore(void *dst, void *src, size_t n);
void flush(void *addr, size_t n);

//#define NTSTORE(dst, src, n) ntstore(dst,src,n) 
//#define FENCE() pmem_drain()
//#define FLUSH(addr, n) flush(addr,n) 

#define NTSTORE(dst, src, n) pmem_memcpy_nodrain(dst, src, n)
#define FENCE() pmem_drain()
#define FLUSH(addr, n) pmem_flush(addr, n)

ssize_t read_redolog(struct slist_head *entries_head, void *dst,
                     void *file_addr, unsigned long offset, unsigned long len);

ssize_t mmio_read_mgl(mmio_t *mmio, int fd, off_t offset, void *buf, size_t len);
ssize_t mmio_write_mgl(mmio_t *mmio, int fd, off_t offset, const void *buf,off_t len, unsigned long tid);

void create_checkpoint_thread(mmio_t *mmio);
void dfs_bitmap(log_table_t* table, void* dst, void* end);
void _checkpoint_mmio(mmio_t *mmio);
void checkpoint_mmio(mmio_t *mmio);
void commit_mmio(mmio_t *mmio);

#endif /* LIBNVMMIO_MMAP_H */
