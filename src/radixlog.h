#ifndef LIBNVMMIO_LOG_H
#define LIBNVMMIO_LOG_H

#include <pthread.h>
#include <stdbool.h>

#include "config.h"
#include "slist.h"
#include "bitmap.h"

#define BITS_PER_LEVEL (6)
#define LARGER_SIZE BITS_PER_LEVEL

#define MIN_SIZE (64)
#define PAGE_SHIFT (12)

#define PTRS_PER_TABLE (1UL << BITS_PER_LEVEL)
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PTRS_PER_PAGE (PAGE_SIZE / MIN_SIZE)
#define OFFSET_SHIFT (PAGE_SHIFT + BITS_PER_LEVEL * 4)
#define LGD_SHIFT (PAGE_SHIFT + BITS_PER_LEVEL * 3)
#define LUD_SHIFT (PAGE_SHIFT + BITS_PER_LEVEL * 2)
#define LMD_SHIFT (PAGE_SHIFT + BITS_PER_LEVEL)
#define LOG_SHIFT(s) (LMD_SHIFT - ((LMD_SHIFT - PAGE_SHIFT) - s))
#define LOG_SIZE(s) (1UL << LOG_SHIFT(s))
#define LOG_MASK(s) (~(LOG_SIZE(s) - 1))
#define LOG_OFFSET(addr, s) (addr & (LOG_SIZE(s) - 1))
#define NR_ENTRIES(s) (1UL << (LMD_SHIFT - LOG_SHIFT(s)))

#define TABLE_MASK ((1UL << (BITS_PER_LEVEL * 3)) - 1)

typedef enum table_type_enum { TABLE = 1, LMD, LUD, LGD } table_type_t;
typedef enum lock_type_enum {RLOCK, WLOCK, IRLOCK, IWLOCK, NOLOCK} lock_type_t;
static const unsigned long TABLE_SIZE[] = {1UL << 12, 1UL << 18, 1UL << 24, 1UL << 30, 1UL << 36}; 

typedef struct index_entry_struct {
  union {
    struct {
      unsigned long united;
    };
    struct {
      unsigned long epoch : 20;
      unsigned long offset : 21;
      unsigned long len : 22;
      unsigned long policy : 1;
    };
  };  
  void *log;
  void *dst;
  unsigned long bitmap[1];
  union {
    struct {
      unsigned long united;
    };
    struct {
      unsigned long rlock : 32;
      unsigned long wlock : 32;
    };
  } lock[2];
  pthread_rwlock_t *rwlockp;
  log_size_t log_size;
  struct slist_head list;
} idx_entry_t;

typedef struct table_struct {
  table_type_t type;
  void* log;
  unsigned long offset;
  struct table_struct* parent;
  pthread_rwlock_t *rwlockp;
  unsigned long bitmap_valid[BITS_TO_LONGS(PTRS_PER_TABLE)];
  unsigned long bitmap[BITS_TO_LONGS(PTRS_PER_TABLE)];
  void *entries[PTRS_PER_TABLE];
  uint8_t lock[64];
  int index;
} log_table_t;

 typedef struct radix_root_struct {
  log_table_t *lgd;
  log_table_t *skip;
  log_table_t *prev_table;
  unsigned long prev_table_index;
} radix_root_t;

typedef struct Bitmap_Operation_Log {
  unsigned long *bitmap;
  unsigned int start;
  unsigned int nbits;
  void* locked_entry;
  log_table_t* table;
  int type;
  unsigned long index;
} bitmap_Op_log;

typedef struct LOG {
    unsigned long tid;
    unsigned long inumber;
    unsigned long offset;
    unsigned long len;
    unsigned long fsize;
    unsigned long checksum;
    unsigned long bitmap[10];
} Log;

typedef struct bitmap_log_struct {
  void* log;
} bitmap_log_t;

typedef enum DFS_NODE_TYPE {LR_TABLE, L_TABLE, R_TABLE, LOCKREAD, LOCK_ONLY, READ_ONLY} node_type;
typedef struct DFS_NODE {
  void *entry;
  void* parent;
  unsigned long index;
  unsigned long offset;
  unsigned long len;
  void* src;
  void* dst;
  node_type type;
} dfs_node;

#define LGD_INDEX(OFFSET) (OFFSET >> LGD_SHIFT) & (PTRS_PER_TABLE - 1)
#define LUD_INDEX(OFFSET) (OFFSET >> LUD_SHIFT) & (PTRS_PER_TABLE - 1)
#define LMD_INDEX(OFFSET) (OFFSET >> LMD_SHIFT) & (PTRS_PER_TABLE - 1)

#define TABLE_INDEX(LOGSIZE, OFFSET) \
  (OFFSET >> LOG_SHIFT(LOGSIZE)) & (NR_ENTRIES(LOGSIZE) - 1)

#define NEXT_TABLE_TYPE(TYPE) (TYPE - 1)

table_type_t get_deepest_table_type(unsigned long filesize);
void init_radixlog(radix_root_t *root, unsigned long filesize);
log_table_t *get_log_table(radix_root_t *root, unsigned long offset);
log_table_t *find_log_table(radix_root_t *root, unsigned long offset);
log_size_t set_log_size(unsigned long offset, size_t len);
idx_entry_t *get_page_entry(log_table_t *table,unsigned long index);
log_table_t *get_table_entry(log_table_t *table,unsigned long index);
idx_entry_t *get_log_entry(unsigned long epoch, log_table_t *table,
                           unsigned long index, log_size_t log_size);
bool check_prev_table(unsigned long prev_table_index, unsigned long offset);

unsigned long get_table_index(unsigned long offset, table_type_t type);

#endif /* LIBNVMMIO_LOG_H */
