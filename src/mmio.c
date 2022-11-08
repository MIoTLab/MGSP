#define _GNU_SOURCE
#include "mmio.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <math.h>

#include "allocator.h"
#include "config.h"
#include "debug.h"
#include "lock.h"

#define MAX_BITMAP_NUMBER 10

extern struct timeval tv_begin[],tv_end[];
extern long long call_number[];
extern long long runtime_us[];
unsigned long write_size = 0;

void ntstore(void *dst, void *src, size_t n) {
  pmem_memcpy_nodrain(dst, src, n);
  write_size+=n;
}

void flush(void *addr, size_t n) {
  pmem_flush(addr, n);
  write_size+=n;
}

#define LOCK_ENTRIES(type_, mmio_, offset_, len_, entries_head_)         \
  do {                                                                   \
    log_table_t *table_;                                                 \
    idx_entry_t *entry_;                                                 \
    log_size_t log_size_;                                                \
    unsigned long index_, log_offset_, log_len_;                         \
    int n_ = len_;                                                       \
    unsigned long off_ = offset_;                                        \
                                                                         \
    while (n_ > 0) {                                                     \
      table_ = get_log_table(&mmio_->radixlog, off_);                    \
      log_size_ = LOG_4K;                                                \
      PRINT("log_size=%lu", LOG_SIZE(log_size_));                        \
      index_ = TABLE_INDEX(log_size_, off_);                             \
      PRINT("TABLE index=%lu", index_);                                  \
                                                                         \
      do {                                                               \
        entry_ = get_page_entry(table_, index_);                         \
      } while (pthread_rwlock_try##type_##lock(entry_->rwlockp) != 0);   \
                                                                         \
      PRINT(#type_ "lock idx_entry, offset=%lu", offset_);               \
                                                                         \
      entry_->log_size = log_size_;                                      \
      slist_push(&entry_->list, &entries_head_);                         \
                                                                         \
      log_offset_ = off_ & (LOG_SIZE(log_size_) - 1);                    \
      log_len_ = LOG_SIZE(log_size_) - log_offset_;                      \
      n_ -= log_len_;                                                    \
      off_ += log_len_;                                                  \
    }                                                                    \
  } while (0)

#define UNLOCK_ENTRIES(entries_head_)                    \
  do {                                                   \
    idx_entry_t *entry_;                                 \
    SLIST_FOR_EACH_ENTRY(entry_, &entries_head_, list) { \
      RWLOCK_UNLOCK(entry_->rwlockp);                    \
      PRINT("unlock idx_entry");                         \
    }                                                    \
  } while (0)

static inline bool check_expend(mmio_t *mmio, off_t offset, size_t len) {
  if (mmio->end <= (mmio->start + offset + len)) {
    return true;
  } else {
    return false;
  }
}

static inline bool check_fsize(mmio_t *mmio, off_t offset, off_t len) {
  if (mmio->fsize < (offset + len)) {
    return true;
  } else {
    return false;
  }
}

static inline void increase_counter(unsigned long *cnt) {
  unsigned long old, new;
  do {
    old = *cnt;
    new = *cnt + 1;
  } while (!__sync_bool_compare_and_swap(cnt, old, new));
}

static inline void increase_size(unsigned long *cnt, long size) {
  unsigned long old, new;
  do {
    old = *cnt;
    new = *cnt + size;
  } while (!__sync_bool_compare_and_swap(cnt, old, new));
}

/*
 * TODO: check conditions
 * 1. FS space
 * 2. RLIMIT_FSIZE
 * 3. interrupt
 */
static void expend_mmio(mmio_t *mmio, int fd, off_t offset, size_t len) {
  unsigned long current_len, new_len;
  int s;

  PRINT("expend memory-mapped file: %lu", mmio->end - mmio->start);
  bravo_read_unlock(&mmio->rwlock);
  bravo_write_lock(&mmio->rwlock);
  table_type_t new_skip_type;
  while (check_expend(mmio, offset, len)) {
    current_len = mmio->end - mmio->start;
    if (current_len >= BASIC_MMAP_SIZE) {
      new_len = current_len << 1;
    } else {
      new_len = BASIC_MMAP_SIZE;
    }

    new_skip_type = get_deepest_table_type(new_len - 1);
    log_table_t* new_skip = mmio->radixlog.lgd;
    while (new_skip->type != new_skip_type) 
      new_skip = new_skip->entries[0];
    PRINT("skip->type = %d", mmio->radixlog.skip->type);
    PRINT("bitmap = %x valid_bitmap = %x", mmio->radixlog.skip->bitmap, mmio->radixlog.skip->bitmap_valid);
    bool exist_log = !bitmap_empty(mmio->radixlog.skip->bitmap,PTRS_PER_TABLE) || !bitmap_empty(mmio->radixlog.skip->bitmap_valid,PTRS_PER_TABLE) ;
    PRINT("exist_log = %d",exist_log);
    while (mmio->radixlog.skip->type != new_skip_type) {
        mmio->radixlog.skip = mmio->radixlog.skip->parent;
        if (exist_log) {
          set_bit(0,mmio->radixlog.skip->bitmap); // 0 is the first bit
          FLUSH(mmio->radixlog.skip->bitmap,1);
        }
    }
    mmio->radixlog.skip = new_skip;

    s = posix_fallocate(fd, 0, new_len);
    if (__glibc_unlikely(s != 0)) {
      HANDLE_ERROR("fallocate");
    }

    mmio->start = mremap(mmio->start, current_len, new_len, MREMAP_MAYMOVE);
    if (__glibc_unlikely(mmio->start == MAP_FAILED)) {
      HANDLE_ERROR("mremap");
    }
    mmio->end = mmio->start + new_len;
  }
  PRINT("expend memory-mapped file: %lu", mmio->end - mmio->start);
  bravo_write_unlock(&mmio->rwlock);
  bravo_read_lock(&mmio->rwlock);
}

void dfs_bitmap(log_table_t* table, void* dst, void* end) {
  unsigned long index1 = find_first_bit(table->bitmap,PTRS_PER_TABLE);
  unsigned long index2 = find_first_bit(table->bitmap_valid,PTRS_PER_TABLE);
  unsigned long index = index1 < index2 ? index1 : index2;
  unsigned long table_size = PAGE_SIZE << (BITS_PER_LEVEL * table->type);
  unsigned long next_size = table_size >> BITS_PER_LEVEL;
  unsigned long log_size;
  PRINT("table->type = %d",table->type);
  PRINT("end - dst = %lu",end-dst);
  PRINT("index = %ld, table_type = %d, table_size = %ld, next_size = %ld", index, table->type, table_size, next_size);
  unsigned long max_index = (end  - dst) % next_size ? (end  - dst) / next_size + 1 : (end  - dst) / next_size;
  max_index = max_index > 64 ? 64 : max_index;
  PRINT("max_index = %d",max_index);
  while (index < max_index) {
    PRINT("index = %lu", index);
    if (table->type > TABLE) {
      log_table_t* entry = table->entries[index];
      if (test_bit(index,table->bitmap_valid)) {
        log_size = next_size < (unsigned long)(end - dst) ? next_size : (unsigned long)(end - dst);
        PRINT("ntstore(%p, %p, %lu)", dst, entry->log, log_size);
        NTSTORE(dst, entry->log, log_size);
      }
      void* new_end = dst + next_size * (index + 1) > end ? end : dst + next_size * (index + 1);
      dfs_bitmap(entry,dst + next_size * index, new_end);
    } else {
      idx_entry_t* entry = table->entries[index];
      if (!test_bit(index,table->bitmap)) {
        log_size = PAGE_SIZE;
        PRINT("ntstore(%p, %p, %lu)", dst + PAGE_SIZE * index, entry->log, log_size);
        NTSTORE(dst + PAGE_SIZE * index, entry->log, log_size);
      } else {
        log_size = MIN_SIZE;
        unsigned long page_index = find_first_bit(entry->bitmap,PTRS_PER_PAGE);
        while (page_index < PTRS_PER_PAGE) {
          log_size = (unsigned long)(end - (dst + PAGE_SIZE * index + MIN_SIZE * page_index));
          log_size = MIN_SIZE <  log_size ? MIN_SIZE : log_size;
          NTSTORE(dst + PAGE_SIZE * index + MIN_SIZE * page_index, entry->log + MIN_SIZE * page_index, log_size);
          clear_bit(page_index,entry->bitmap);
          page_index = find_first_bit(entry->bitmap,PTRS_PER_PAGE);
        }
      }
    }
    clear_bit(index,table->bitmap);
    clear_bit(index,table->bitmap_valid);
    index1 = find_first_bit(table->bitmap,PTRS_PER_TABLE);
    index2 = find_first_bit(table->bitmap_valid,PTRS_PER_TABLE);
    index = index1 < index2 ? index1 : index2;
  }
  FENCE();
}

void _checkpoint_mmio(mmio_t *mmio) {
  PRINT("start checkpointing: mmio->ino=%lu mmio->fsize = %d", mmio->ino,mmio->fsize);
  if (bravo_read_trylock(&mmio->rwlock) == 0) {
    log_table_t* table = mmio->radixlog.skip;
    dfs_bitmap(table,mmio->start,mmio->start + mmio->fsize);
    bravo_read_unlock(&mmio->rwlock);
  }
  PRINT("complete checkpointing mmio->ino=%lu", mmio->ino);
}

static inline void log_bitmap(Log* blog, bitmap_Op_log* boplog, int* blog_index, unsigned long* bitmap, unsigned int start, unsigned int nbits) {
  PRINT("index = %d,bitmap = %p start = %d, nbits = %d",*blog_index,bitmap,start,nbits);
  PRINT("bitmap = %p index_bitmap = %p",bitmap,boplog[*blog_index].bitmap);
  if (bitmap == boplog[*blog_index].bitmap) {
    PRINT("old nbits = %u, nbits = %u",boplog[*blog_index].nbits,nbits);
    boplog[*blog_index].nbits += nbits;
    if (start < boplog[*blog_index].start)
      boplog[*blog_index].start = start;
  } else {
    if (*blog_index >= MAX_BITMAP_NUMBER) {
      for (int i = 0; i < *blog_index-1; i++) {
        PRINT("%p\n",boplog[*blog_index].bitmap);
      }
      HANDLE_ERROR("too many blog");
    }
    boplog[*blog_index].bitmap = bitmap;
    boplog[*blog_index].start = start;
    PRINT("old nbits = %u, nbits = %u",boplog[*blog_index].nbits,nbits);
    boplog[*blog_index].nbits = nbits;
    blog->bitmap[*blog_index] = *bitmap;
    blog->checksum += *bitmap;
  }
  PRINT("index = %d,bitmap = %p start = %d, nbits = %d\n",*blog_index,boplog[*blog_index].bitmap,boplog[*blog_index].start,boplog[*blog_index].nbits);
}

static inline void log_lock(bitmap_Op_log* boplog, int* blog_index, void* locked_entry, int type) {
  PRINT("log lock %d",*blog_index);
  if (boplog[*blog_index].locked_entry != NULL && boplog[*blog_index].locked_entry != locked_entry)
    (*blog_index) ++;
  if (boplog[*blog_index].locked_entry != locked_entry) {
    boplog[*blog_index].locked_entry = locked_entry;                                          
    boplog[*blog_index].type = type;           
    boplog[*blog_index].bitmap = NULL;           
    boplog[*blog_index].table = NULL;                                   
  }
}

#define SET_META_LOG(blog_,boplog_,mmio_,offset_,len_,tid_)                           \
  do {                                                                                \
    unsigned long index_ = tid % BMAP_SIZE;                                           \
    blog_ = (Log*)(mmio_->bitmaplog.log) + index_;                                    \
    while (blog_->len != 0 && blog_->tid != tid_) {                                   \
      index_ = (index_ + 1) % BMAP_SIZE;                                              \
      blog_ = (Log*)(mmio_->bitmaplog.log) + index_;                                  \
    }                                                                                 \
    blog_->checksum = 0;                                                              \
    blog_->inumber = mmio_->ino;                                                      \
    blog_->tid = tid_;                                                                \
    blog_->fsize = mmio_->fsize;                                                      \
    blog_->offset = offset_;                                                          \
    blog_->len = 0;                                                                   \
    for (int i = 0; i < MAX_BITMAP_NUMBER; i++) boplog_[i].locked_entry = NULL;                       \
  } while (0)                                                           
/*
static inline void lock_entry(idx_entry_t* entry, unsigned long left_index, unsigned long right_index, lock_type_t lock_type) {
  PRINT("LOCK ENTRY %p %lu %lu %d\n",entry,left_index,right_index,lock_type);
  unsigned long old,new,index_r,index_w,index;
  unsigned long* bitmap;
  unsigned long nbits = (left_index < 32 && right_index >= 32) ? 32 - left_index : right_index - left_index + 1;

  while (nbits > 0) {
    index_r = left_index % 32;
    index_w = index_r + 32;
    index = lock_type == RLOCK ? index_r : index_w;
    bitmap = &(entry->lock[left_index/32].united);
    PRINT("index_r = %lu index_w = %lu nbits = %lu,bitmap = %p",index_r,index_w,nbits,bitmap);
    do {
      old = *bitmap;
      new = old;
      if (new >> index_w % (1 << nbits)) continue;
      if (lock_type == WLOCK && new >> index_r % (1 << nbits)) continue;
      new = (new >> (index + nbits) << (index + nbits)) + (((1 << nbits) - 1) << index) + new % (1 << index);
    } while(!__sync_bool_compare_and_swap(bitmap, old, new));   
    nbits = (left_index < 32 && right_index >= 32) ? right_index - 32 + 1 : 0;
    left_index = 32;
  }
}

static inline void unlock_entry(idx_entry_t* entry, unsigned long left_index, unsigned long right_index, lock_type_t lock_type) {
  PRINT("UNLOCK ENTRY %p %lu %lu %d",entry,left_index,right_index,lock_type);
  PRINT("entry->log = %p",entry->log);
  unsigned long old,new,index_r, index;
  unsigned long* bitmap;
  unsigned long nbits = (left_index < 32 && right_index >= 32) ? 32 - left_index : right_index - left_index + 1;

  while (nbits > 0) {
    index_r = left_index % 32;
    index = lock_type == RLOCK ? index_r : index_r + 32;
    bitmap = &(entry->lock[left_index/32].united);
    do {
      old = *bitmap;
      new = old;
      new = (new >> (index + nbits) << (index + nbits)) + new % (1 << index);
    } while(!__sync_bool_compare_and_swap(bitmap, old, new));   
    nbits = (left_index < 32 && right_index >= 32) ? right_index - 32 + 1 : 0;
    left_index = 32;
  }
  PRINT("entry->log = %p",entry->log);
}
*/
#define EMPTY_LOCK 0
#define FULL_LOCK 63

#define TEST_IRLOCK(lock) ((*lock) & 128)
#define TEST_IWLOCK(lock) ((*lock) & 64)
#define TEST_RLOCK(lock) (((*lock) & 63) > 0 && ((*lock) & 63) < 63)
#define TEST_WLOCK(lock) (((*lock) & 63) == FULL_LOCK)
#define TEST_RWLOCK(lock) (TEST_RLOCK(lock) || TEST_WLOCK(lock))
#define TEST_IRIWLOCK(lock) (TEST_IRLOCK(lock) || TEST_IWLOCK(lock))
#define TEST_FULLRLOCK(lock) (((*lock) & 63) == (FULL_LOCK - 1))

#define SET_LOCK(lock, value) __sync_lock_test_and_set(lock, value)

#define SET_FULLLOCK(lock)                                                           \
do {                                                                                 \
 do {                                                                                \
   PRINT("WLOCK\n");\
 } while(!__sync_bool_compare_and_swap(lock, EMPTY_LOCK, FULL_LOCK));                \
} while(0)

#define CLEAN_FULLLOCK(lock)                                                         \
do {                                                                                 \
 do {                                                                                \
  if(*lock != 63)HANDLE_ERROR("write unlock = %d\n", *lock);                         \
  PRINT("UNWLOCK\n");\
 } while(!__sync_bool_compare_and_swap(lock, FULL_LOCK, EMPTY_LOCK));                \
} while(0)

#define SET_READLOCK(lock)                                                           \
do {                                                                                 \
  uint8_t old_, new_;                                                                \
  do {                                                                                \
    old_ = *lock;                                                                     \
    if (TEST_WLOCK(lock) || TEST_FULLRLOCK(lock)) old_ = 0;                          \
    new_ = old_ + 1;                                                                  \
  } while(!__sync_bool_compare_and_swap(lock, old_, new_));                           \
} while(0)

#define CLEAN_READLOCK(lock)                                                         \
do {                                                                                 \
 uint8_t old_, new_;                                                                 \
 do {                                                                                \
    old_ = *lock;                                                                    \
    new_ = old_ - 1;                                                                 \
    if (new_ > old_) HANDLE_ERROR("Too much read unlock");                           \
 } while(!__sync_bool_compare_and_swap(lock, old_, new_));                           \
} while(0)

static inline bool lock_table(log_table_t* table, unsigned long index, lock_type_t lock_type){
  if (lock_type == RLOCK && table->type > TABLE) {
    PRINT("lock_table: table->type = %d\n",table->type);
  }
  PRINT("LOCK TABLE %p %lu %d",table,index,lock_type);
  uint8_t new, old;
  uint8_t* lock = &table->lock[index];
  do { 
    old = *lock;
    if ((old & 63) != 63 && (old & 63) > 32)
      HANDLE_ERROR("wrong lock value %d", old);
    new = old;
    PRINT("old = %d new = %d",old,new);
    switch (lock_type) {
      case RLOCK:
        PRINT("RLOCK %d, table = %p index = %d\n", *lock, table, index);
        if (TEST_WLOCK(lock) || TEST_FULLRLOCK(lock)) { PRINT("Wlock = %d fulllock = %d\n",TEST_WLOCK(lock), TEST_FULLRLOCK(lock));old = *lock - 1; new = old; continue;}
        if (TEST_IWLOCK(lock)) {
            PRINT("Rlock_table: TEST_IRIWLOCK\n");
            uint8_t old_value = *lock;
            if (__sync_bool_compare_and_swap(lock, old_value, FULL_LOCK)) {
              log_table_t* next_table = get_table_entry(table, index);
              for (int i = 0; i < (int)PTRS_PER_TABLE; i ++)
                SET_READLOCK(&next_table->lock[i]);
              SET_LOCK(lock, 1);
              for (int i = 0; i < (int)PTRS_PER_TABLE; i ++)
                CLEAN_READLOCK(&next_table->lock[i]);
              return true;
            } else {
              old = 0; continue;
            }
        }
        new = old + 1;
        break;
      case WLOCK:
        if (TEST_IRIWLOCK(lock)) {
          PRINT("Wlock_table: TEST_IRIWLOCK\n");
          uint8_t old_value = *lock;
          if (__sync_bool_compare_and_swap(lock, old_value, FULL_LOCK)) {
            log_table_t* next_table = get_table_entry(table, index);
            for (int i = 0; i < (int)PTRS_PER_TABLE; i ++)
              SET_FULLLOCK(&next_table->lock[i]);
            for (int i = 0; i < (int)PTRS_PER_TABLE; i ++)
              CLEAN_FULLLOCK(&next_table->lock[i]);
            return true;
          } else {
            old = 0; continue;
          }
        }
        old = EMPTY_LOCK;
        new = FULL_LOCK;
        break;
      case IRLOCK:
        if (TEST_WLOCK(lock)) {old = 0; continue;}
        if (TEST_IRLOCK(lock)) return true;
        new = old | 128;
        break;
      case IWLOCK:
        if (TEST_IWLOCK(lock)) return true;
        if (TEST_RWLOCK(lock)) {old = 0;continue;}
        new = old | 64;
        break;
      default:
        return false;
    }
    if ((new & 63) != 63 && (new & 63) > 32)
      HANDLE_ERROR("wrong lock value %d lock = %d old = %d table->type = %d lock_type = %d", new, *lock, old, table->type, lock_type);
  } while(!__sync_bool_compare_and_swap(lock, old, new)); 
  return true;
}

#define GET_NEXT_LEVEL_TABLE(table_,offset_)                                          \
  do {                                                                                \
    unsigned long index_ = get_table_index(offset_,table_->type);                     \
    PRINT("index = %d",index_);\
    log_table_t * next_level_table_ = table_->entries[index_];                        \
    if (next_level_table_ == NULL)                                                    \
      ALLOC_TABLE(next_level_table_, NEXT_TABLE_TYPE(table_->type), table_, index_);  \
    table_ = next_level_table_;                                                       \
  } while (0)                                                           

#define GET_NEXT_TABLE(table_,subtree_, dst_,dst_offset_,offset_,size_,lock_type)     \
  do {                                                                                \
    PRINT("table->type = %d offset = %d len = %d", table_->type, offset_, size_);     \
    unsigned long off_ = (offset_ << (BITS_PER_LEVEL * (LGD - table_->type))) & ((1UL << OFFSET_SHIFT) - 1); \
    if (!(                                                                            \
      table_->type > TABLE && \
        (offset_ >> (BITS_PER_LEVEL * (table_->type - TABLE) + PAGE_SHIFT)) ==          \
        ((offset_ + size_) >> (BITS_PER_LEVEL * (table_->type - TABLE) + PAGE_SHIFT)) &&(\
        (off_ << BITS_PER_LEVEL) & ((1UL << OFFSET_SHIFT) - 1) ||                     \
          (unsigned long)(size_) < PAGE_SIZE<<(BITS_PER_LEVEL*NEXT_TABLE_TYPE(table_->type))\
      ) ))                                                                            \
      break;                                                                          \
    bool valid_subtree = false;                                                       \
    while (true) {                                                                    \
      GET_NEXT_LEVEL_TABLE(table_,offset_);                                           \
      if (test_bit(table_->index,table_->parent->bitmap_valid)) {                     \
        dst_offset_ = offset_ & (TABLE_SIZE[table_->type] - 1);                       \
        dst_ = table_->log;                                                           \
        subtree_ = table_;                                                            \
        valid_subtree = true;                                                         \
      } else if (!valid_subtree)                                                      \
        subtree_ = table_;                                                            \
      if ((off_ << BITS_PER_LEVEL) & ((1UL << OFFSET_SHIFT) - 1))                     \
        off_ <<= BITS_PER_LEVEL;                                                      \
      PRINT("index = %d table = %p table->parent = %p\n", table_->index, table_, table_->parent);\
      if (!test_bit(table_->index,table_->parent->bitmap)) {                          \
        bool changed = false;                                                         \
        if (!bitmap_empty(table_->bitmap,PTRS_PER_TABLE)) {                           \
          bitmap_zero(table_->bitmap,PTRS_PER_TABLE);                                 \
          changed = true;                                                             \
        }                                                                             \
        if (!bitmap_empty(table_->bitmap_valid,PTRS_PER_TABLE)) {                     \
          bitmap_zero(table_->bitmap_valid,PTRS_PER_TABLE);                           \
          changed = true;                                                             \
        }                                                                             \
        if (changed) FLUSH(table_->bitmap_valid,BYTE_PER_LONG*2);                     \
        set_bit(table_->index,table_->parent->bitmap);                                \
      }                                                                               \
      if (!(                                                                           \
      table_->type > TABLE && \
        (offset_ >> (BITS_PER_LEVEL * (table_->type - TABLE) + PAGE_SHIFT)) ==          \
        ((offset_ + size_) >> (BITS_PER_LEVEL * (table_->type - TABLE) + PAGE_SHIFT)) &&(\
        (off_ << BITS_PER_LEVEL) & ((1UL << OFFSET_SHIFT) - 1) ||                     \
          (unsigned long)(size_) < PAGE_SIZE<<(BITS_PER_LEVEL*NEXT_TABLE_TYPE(table_->type))\
      ) ))                                                                            \
        break;                                                                        \
        PRINT("test1 lock_type = %d\n",lock_type);\
      lock_table(table_->parent,table_->index,lock_type);                             \
      PRINT("test\n");\
    }                                                                                 \
  } while (0)                                      

#define WRITE_LARGE_SIZE(table,index,dst,dst_offset,src,log_len,blog,boplog,blog_index,fgl_,write_back_) \
  do {                                                                                \
    PRINT("WRITE_LARGE_SIZE");                                                        \
    log_table_t* table_ = table->entries[index];                                      \
    if (fgl_) lock_table(table,index,WLOCK);                                          \
    log_lock(boplog,&blog_index,table,table->type);                                   \
    if (table_ == NULL)                                                               \
      ALLOC_TABLE(table_,NEXT_TABLE_TYPE(table->type),table,index);                   \
    if (table_->log == NULL) {                                                        \
      table_->log = alloc_log_data(LARGER_SIZE);                                      \
      FLUSH(&table_->log,sizeof(table_->log));                                        \
    }                                                                                 \
    void* log_ = table_->log;                                                         \
    if (test_bit(index,table->bitmap_valid))                                          \
      NTSTORE(dst + dst_offset, src, log_len);                                        \
    else {                                                                            \
      NTSTORE(log_, src, log_len);                                                    \
      if (write_back_) memcpy(dst + dst_offset, src, log_len);                        \
    }                                                                                 \
    log_bitmap(blog,boplog,&blog_index,table->bitmap_valid,index,1);                  \
    if (test_bit(index,table->bitmap))                                                \
      clear_bit(index, table->bitmap);                                                \
  } while (0)                                                                         

//  if (fgl_) lock_table(table,index,WLOCK);                                            

#define WRITE_PAGE(table,index,log_,dst,dst_offset,src,blog,boplog,blog_index,fgl_,write_back_)   \
do {                                                                                  \
  PRINT("WRITE_PAGE");                                                                \
  log_lock(boplog,&blog_index,table,table->type);                                     \
  PRINT("write fd = %d tid = %d lock %p %d lock = %d\n", fd, tid, table, index, table->lock[index]); \
  if (fgl_) SET_FULLLOCK(&(table->lock[index]));                                    \
  PRINT("fd = %d locked %p %d fgl = %d lock = %d\n", fd, table, index, fgl_, table->lock[index]); \
  if (test_bit(index,table->bitmap_valid)) {                                          \
    PRINT("dst ntstore(%p, %p, %lu)", dst + dst_offset, src, PAGE_SIZE);              \
    NTSTORE(dst + dst_offset, src, PAGE_SIZE);                                        \
  } else {                                                                            \
    PRINT("log ntstore(%p, %p, %lu)", log_, src ,PAGE_SIZE);                          \
    NTSTORE(log_, src,PAGE_SIZE);                                                     \
    PRINT("write_back = %d %p, %d,log memcpy(%p, %p, %lu)\n", write_back_, dst, dst_offset, dst + dst_offset, src ,PAGE_SIZE);\
    if (write_back_) memcpy(dst + dst_offset, src,PAGE_SIZE);                         \
    PRINT("log memcpy(%p, %d, %p, %lu)\n", dst, dst_offset, src ,PAGE_SIZE);          \
  }                                                                                   \
  clear_bit(index,table->bitmap);                                                     \
  log_bitmap(blog,boplog,&blog_index,table->bitmap_valid,index,1);                    \
} while(0) 


#define WRITE_SMALL_SIZE(left_index,log_entry,left_offset,dst,dst_offset,log_,log_offset \
        ,src,src_offset,log_len,last_len,blog,boplog,blog_index,write_back_)             \
do {                                                                                     \
  PRINT("WRITE_SMALL_SIZE\n");                                                          \
  if (test_bit(left_index,log_entry->bitmap)) {                                          \
    if (left_offset) {                                                                   \
      NTSTORE(dst + dst_offset - left_offset, log_ + log_offset - left_offset, left_offset);                     \
      PRINT("ntstore(%p, %p, %u)", dst + dst_offset - left_offset, log_ + log_offset - left_offset, left_offset);\
    }                                                                                    \
    NTSTORE(dst + dst_offset, src + src_offset, log_len);                                \
    PRINT("ntstore(%p, %p, %lu)", dst + dst_offset, src + src_offset, log_len);          \
    last_len = (log_len + MIN_SIZE - right_offset) < last_len ?  (log_len + MIN_SIZE - right_offset) : last_len; \
    if (right_offset && last_len > log_len) {                                            \
      PRINT("ntstore(%p, %p, %lu)", dst + dst_offset + log_len, log_ + log_offset + log_len, last_len - log_len);\
      NTSTORE(dst + dst_offset + log_len, log_ + log_offset + log_len, last_len - log_len);                      \
      PRINT("ntstore(%p, %p, %lu)", dst + dst_offset + log_len, log_ + log_offset + log_len, last_len - log_len);\
    }                                                                                    \
  } else {                                                                               \
    if (left_offset) {                                                                   \
      NTSTORE(log_ + log_offset - left_offset, dst + dst_offset - left_offset, left_offset);                     \
      if (write_back_) memcpy(dst + dst_offset - left_offset, log_ + log_offset - left_offset, left_offset);     \
      PRINT("ntstore(%p, %p, %u)", log_ + log_offset - left_offset, dst + dst_offset - left_offset, left_offset);\
    }                                                                                    \
    NTSTORE(log_ + log_offset, src + src_offset, log_len);                               \
    if (write_back_) memcpy(dst + dst_offset, src + src_offset, log_len);                \
    PRINT("ntstore(%p, %p, %lu)", log_ + log_offset, src, log_len);                      \
    PRINT("last_len = %lu new_len = %lu",last_len, log_len + MIN_SIZE - right_offset);   \
    last_len = ((log_len + MIN_SIZE - right_offset) < last_len) ?  (log_len + MIN_SIZE - right_offset) : last_len; \
    PRINT("last_len = %lu log_len = %lu",last_len, log_len);                             \
    if (right_offset && (last_len > log_len)) {                                          \
      NTSTORE(log_ + log_offset + log_len, dst + dst_offset + log_len, last_len - log_len);                        \
      if(write_back_) memcpy(dst + dst_offset + log_len, log_ + log_offset + log_len, last_len - log_len);         \
      PRINT("ntstore(%p, %p, %lu)", log_ + log_offset + log_len, dst + dst_offset + log_len, last_len - log_len);  \
    }                                                                                    \
  }                                                                                      \
  log_bitmap(blog,boplog,&blog_index,log_entry->bitmap,left_index,1);                    \
  left_index ++;                                                                         \
  PRINT("WRITE_SMALL_SIZE len = %d\n",log_len);                                                          \
} while(0)

#define WRITE_RIGHT_BLOCK(right_index,log_entry,right_offset,dst,dst_offset,log_,log_offset \
        ,src,src_offset,log_len,last_len,blog,boplog,blog_index,write_back_)                \
do {                                                                                        \
  PRINT("WRITE_RIGHT_BLOCK");                                                               \
  last_len = (log_len + MIN_SIZE - right_offset) < last_len ?  (log_len + MIN_SIZE - right_offset) : last_len; \
  PRINT("last_len = %lu", last_len);                                                        \
  if (test_bit(right_index,log_entry->bitmap)) {                                            \
    NTSTORE(dst + dst_offset + log_len - right_offset, src + log_len - right_offset, right_offset);  \
    PRINT("right block: ntstore(%p, %p, %d)", dst + dst_offset + log_len - right_offset, src + log_len - right_offset, right_offset); \
    if (last_len > log_len) {                                                               \
      NTSTORE(dst + dst_offset + log_len, log_ + log_offset + log_len, last_len - log_len); \
      PRINT("right block: ntstore(%p, %p, %ld)", dst + dst_offset + log_len, log_ + log_offset + log_len, last_len - log_len); \
    }                                                                                       \
  } else {                                                                                  \
    NTSTORE(log_ + log_offset + log_len - right_offset, src + log_len - right_offset, right_offset); \
    if (write_back_) {memcpy(dst + dst_offset + log_len - right_offset, src + log_len - right_offset, right_offset);}\
    PRINT("right block log: ntstore(%p, %p, %d)", log_ + log_offset + log_len - right_offset,  src + log_len - right_offset, right_offset); \
    if (last_len > log_len) {                                                               \
      NTSTORE(log_ + log_offset + log_len, dst + dst_offset + log_len, last_len - log_len); \
      PRINT("right block log : ntstore(%p, %p, %ld)", log_ + log_offset + log_len, dst + dst_offset + log_len,  last_len - log_len);  \
    }                                                                                       \
  }                                                                                         \
  log_bitmap(blog,boplog,&blog_index,log_entry->bitmap,right_index,1);                      \
  right_index --;                                                                           \
  PRINT("WRITE_SMALL_SIZE len = %d\n",right_offset);                                                          \
} while(0)

#define WRITE_LEFT_BLOCK(left_index,log_entry,left_offset,dst,dst_offset,log_,log_offset   \
        ,src,src_offset,log_len,last_len,blog,boplog,blog_index,write_back_)               \
do {                                                                                       \
  PRINT("WRITE_LEFT_BLOCK len = %d\n", MIN_SIZE - left_offset);                           \
  if (test_bit(left_index,log_entry->bitmap)) {                                            \
    PRINT("Bit setted");                                                                   \
    NTSTORE(dst + dst_offset - left_offset, log_ + log_offset - left_offset, left_offset); \
    NTSTORE(dst + dst_offset, src, MIN_SIZE - left_offset);                                \
    PRINT("left block: ntstore(%p, %p, %d)", dst + dst_offset - left_offset,  log_ + log_offset - left_offset, left_offset); \
    PRINT("left block: ntstore(%p, %p, %d)", dst + dst_offset, src,  MIN_SIZE - left_offset); \
  } else {                                                                                 \
    PRINT("log = %p, log_offset = %lu", log_ + log_offset, log_offset);                    \
    NTSTORE(log_ + log_offset - left_offset, dst + dst_offset - left_offset, left_offset); \
    PRINT("left block log: ntstore(%p, %p, %d)", log_ + log_offset - left_offset, dst + dst_offset - left_offset, left_offset); \
    if (write_back_) memcpy(dst + dst_offset - left_offset, log_ + log_offset - left_offset, left_offset);\
    NTSTORE(log_ + log_offset, src, MIN_SIZE - left_offset);                               \
    if(write_back_)  memcpy(dst + dst_offset, src, MIN_SIZE - left_offset);                \
    PRINT("left block log: ntstore(%p, %p, %d)", log_ + log_offset, src, MIN_SIZE - left_offset); \
  }                                                                                        \
  log_bitmap(blog,boplog,&blog_index,log_entry->bitmap,left_index,1);                      \
  left_index ++;                                                                           \
  dst_offset += (MIN_SIZE - left_offset);                                                  \
  log_offset += (MIN_SIZE - left_offset);                                                  \
  src_offset += (MIN_SIZE - left_offset);                                                  \
} while (0)

#define WRITE_MIDDLE_BLOCK(left_index,next,log_entry,right_index,dst,dst_off_,log_,log_offset \
        ,src,src_offset,log_len,last_len,blog,boplog,blog_index,write_back_)               \
do {                                                                                       \
  PRINT("WRITE_MIDDLE_BLOCK");                                                             \
  int length;                                                                              \
  if (test_bit(left_index,log_entry->bitmap)) {                                            \
    bitmap = ~(~0UL >> (BITS_PER_LONG - left_index - 1) | log_entry->bitmap[0]);           \
    next = __ffs(bitmap);                                                                  \
    next = (next > right_index + 1 || next == 0 || next == 63) ? right_index + 1 : next;   \
    length = next - left_index;                                                            \
    NTSTORE(dst + dst_off_, src + src_offset, length * MIN_SIZE);                           \
    PRINT("middle block: ntstore(%p, %p, %d)", dst + dst_off_, src + src_offset, length * MIN_SIZE); \
  } else {                                                                                 \
    bitmap = ~0UL << left_index & log_entry->bitmap[0];                                    \
    next = __ffs(bitmap);                                                                  \
    next = (next > right_index + 1 || next == 0 || next == 63) ? right_index + 1 : next;   \
    length = next - left_index;                                                            \
    NTSTORE(log_ + log_offset, src + src_offset, length * MIN_SIZE);                       \
    PRINT("middle block log: ntstore(%p, %p, %d)", log_ + log_offset, src + src_offset, length * MIN_SIZE); \
    if (write_back_) memcpy(dst + dst_off_, src + src_offset, length * MIN_SIZE);           \
  }                                                                                        \
  log_bitmap(blog,boplog,&blog_index,log_entry->bitmap,left_index,length);                 \
  dst_off_ += length * MIN_SIZE;                                                         \
  log_offset += length * MIN_SIZE;                                                         \
  src_offset += length * MIN_SIZE;                                                         \
  PRINT("WRITE_MIDDLE_BLOCK len = %d\n", length * MIN_SIZE);                               \
} while (0)

ssize_t mmio_write_mgl(mmio_t *mmio, int fd, off_t offset, const void *buf, off_t len, unsigned long tid) {
  PRINT("tid = %d\n", tid);
  PRINT("mmio=%p, offset=%ld, buf=%p, len=%ld\n", mmio, offset, buf, len); 
  /*
   * Acquire the reader-locks of the mmio.
   */
  bravo_read_lock(&mmio->rwlock);
  PRINT("mmio->start=%p mmio->end=%p mmio->start + offset + len = %p, offset=%ld len=%ld", mmio->start,mmio->end,mmio->start+offset+len,offset,len);
  if (__glibc_unlikely(check_expend(mmio, offset, len))) {
    PRINT("mmio->start=%p mmio->end=%p mmio->start + offset + len = %p, offset=%ld len=%ld", mmio->start,mmio->end,mmio->start+offset+len,offset,len);
    expend_mmio(mmio, fd, offset, len);
    PRINT("mmio->start=%p mmio->end=%p mmio->start + offset + len = %p, offset=%ld len=%ld", mmio->start,mmio->end,mmio->start+offset+len,offset,len);
  }
  PRINT("fd = %d mmio->end - mmio->start = %ld\n", fd, mmio->end - mmio->start);
  Log* blog;
  bitmap_Op_log boplog[MAX_BITMAP_NUMBER];
  int blog_index = 0;     
  SET_META_LOG(blog,boplog,mmio,offset,len,tid);
  void *dst, *src = (void*)buf;
  off_t off= offset, dst_offset;
  off_t ret = 0;
  log_table_t *table, *subtree = NULL;  
  log_table_t *prev_table = mmio->radixlog.prev_table;
  bool large_size = false;
  unsigned long last_len = 0, log_offset = 0, log_len = 0, index = 0;
  log_size_t log_size;

  bool fgl = (mmio->policy_l == FINELOCK);
  if (!fgl) {
    SET_FULLLOCK(&(mmio->lock));
  } else {
    //while (mmio->lock) PRINT("fd = %d lock = %d\n",fd ,mmio->lock);
  }
  
  if (prev_table->offset <= (unsigned long)offset && prev_table->offset + TABLE_SIZE[prev_table->type] >= (unsigned long)(offset + len)) {       
    PRINT("use prev_table %d", prev_table->type);
    subtree = prev_table;                                                                                        
  } else {
    if (prev_table->index!=63 && prev_table->offset + TABLE_SIZE[prev_table->type] <= (unsigned long)offset && prev_table->offset + 2 * TABLE_SIZE[prev_table->type] >= (unsigned long)(offset + len)) {
      PRINT("use next prev_table %d", prev_table->type);
      set_bit(prev_table->index + 1, prev_table->parent->bitmap);
      log_table_t* next = get_table_entry(prev_table->parent,prev_table->index + 1);
      subtree = next;
    } else {
    PRINT("use new table");
  }
  } 
  subtree = subtree ? subtree : mmio->radixlog.skip;
  //subtree = mmio->radixlog.skip;
  table = subtree;
  PRINT("subtree = %p table->type = %d",table,table->type);
  GET_NEXT_TABLE(table,subtree,dst,dst_offset,off,len,IWLOCK);
  PRINT("table = %p table->type = %d subtree = %p",table, table->type, subtree);
    
  dst = mmio->start;
  dst_offset = off;
  bool write_back = (mmio->policy_g == READOPT);
  while (len > ret) {   
    unsigned long dst_off = dst_offset;
    table = subtree;
    last_len = mmio->fsize > off ? (unsigned long)(mmio->fsize - off) : 0;
    while (table->type >= TABLE) {
      log_size = TABLE_SIZE[NEXT_TABLE_TYPE(table->type)];
      log_offset = off & (log_size - 1);
      log_len = log_size - log_offset > (unsigned long)(len-ret) ? (unsigned long)(len-ret) : log_size - log_offset;                                           
      index = get_table_index(off, table->type);
      PRINT("index = %d",index);                           
      if (table->type == TABLE || log_len > TABLE_SIZE[table->type - 2])
        break;  
      set_bit(index,table->bitmap);     
      if (fgl) lock_table(table,index,IWLOCK);
      PRINT("table = %p subtree = %p test bit bitmap = %d test valid = %d",table, subtree, test_bit(3, table->bitmap),test_bit(3, table->bitmap_valid));
      table = get_table_entry(table,index);
    }
    PRINT("table = %p",table);
    PRINT("index = %lu, table->type = %d log_len = %lu last_len = %lu", index, table->type, log_len, last_len);
    if (table->type > LMD)
      HANDLE_ERROR("Larger Write!");
    if (table->type > TABLE) {    
      large_size = true;
      WRITE_LARGE_SIZE(table,index,dst,dst_offset,src,log_len,blog,boplog,blog_index,fgl,write_back);
    } else {
      PRINT("log_entry = %p",table->entries[index]);
      idx_entry_t* log_entry = get_page_entry(table,index);
      PRINT("log_entry = %p", log_entry);
      PRINT("log = %p", log_entry->log);
      void* log_ = log_entry->log;
      if (log_len == PAGE_SIZE) {
        //call_number[2]++;
        //gettimeofday(&tv_begin[2], NULL);
        WRITE_PAGE(table,index,log_,dst,dst_offset,src,blog,boplog,blog_index,fgl,write_back);
        //gettimeofday(&tv_end[2], NULL);
        //runtime_us[2]+=((tv_end[2].tv_sec - tv_begin[2].tv_sec) * 1000000 + tv_end[2].tv_usec - tv_begin[2].tv_usec);
      } else {
        if (fgl) {
          SET_FULLLOCK(&(table->lock[index]));
        }
        log_lock(boplog,&blog_index,log_entry,-1);
        boplog[blog_index].table = table; 
        boplog[blog_index].index = index;  
        if (!test_bit(index,table->bitmap)) {
          if (!test_bit(index,table->bitmap_valid)) {
            if (!bitmap_empty(log_entry->bitmap,PTRS_PER_PAGE))
              bitmap_clear(log_entry->bitmap,0,PTRS_PER_PAGE);
          } else {
            unsigned long tmp = ~(log_entry->bitmap[0]);
            if (!bitmap_empty(&tmp,PTRS_PER_PAGE))
              bitmap_set(log_entry->bitmap,0,PTRS_PER_PAGE);
          }
          set_bit(index,table->bitmap);
          //FLUSH(table->bitmap,BYTE_PER_LONG);
          PRINT("set index = %lu of table->type = %d", index, table->type);
        }
        PRINT("table = %p bitmap = %lu bitmap_valid = %lu",table, table->bitmap[0], table->bitmap_valid[0]);
        int left_index = log_offset / MIN_SIZE;
        int right_index = (log_offset + log_len - 1) / MIN_SIZE;
        unsigned int left_offset = log_offset % MIN_SIZE, right_offset = (log_offset + log_len) % MIN_SIZE;
        unsigned long bitmap;
        unsigned long src_offset = 0;
        
        //lock_entry(log_entry,left_index,right_index,WLOCK);
        //log_lock(boplog,&blog_index,log_entry,0);  
        /*Deal with the left most and right most half block*/
        PRINT("log_offset = %lu, log_len = %lu", log_offset, log_len); 
        PRINT("left_index = %d, left_offset = %d, right_index = %d, right_offset = %d", left_index, left_offset, right_index, right_offset); 
        if (left_index == right_index) {
          WRITE_SMALL_SIZE(left_index,log_entry,left_offset,dst,dst_off,log_,log_offset,src,src_offset,log_len,last_len,blog,boplog,blog_index,write_back);
        } else {
          if (right_offset) {
            WRITE_RIGHT_BLOCK(right_index,log_entry,right_offset,dst,dst_off,log_,log_offset,src,src_offset,log_len,last_len,blog,boplog,blog_index,write_back); 
          }
          if (left_offset) {
            WRITE_LEFT_BLOCK(left_index,log_entry,left_offset,dst,dst_off,log_,log_offset,src,src_offset,log_len,last_len,blog,boplog,blog_index,write_back); 
          }
        }
        /*Deal with the middle blocks*/
        PRINT("left_index = %d, right_index = %d", left_index, right_index); 
        int next;      
        while (left_index <= right_index) {
          WRITE_MIDDLE_BLOCK(left_index,next,log_entry,right_index,dst,dst_off,log_,log_offset,src,src_offset,log_len,last_len,blog,boplog,blog_index,write_back);
          left_index = next;                       
        }
        PRINT("table = %p bitmap = %lu bitmap_valid = %lu",table, table->bitmap[0], table->bitmap_valid[0]);
      } 
    }
    PRINT("Write %lu %ld",log_len,off); 
    ret += log_len;
    off += log_len;
    PRINT("dst_offset = %d",dst_offset);
    dst_offset += log_len;
    src += log_len;
  }
  //NTSTORE(mmio->start + offset,src,len);
  //if (offset > 1*len) NTSTORE(mmio->start + offset - 1*len, src, len*1); else NTSTORE(mmio->start + offset  +len, src, len*1);
  if (subtree != prev_table) {
    __sync_bool_compare_and_swap(&mmio->radixlog.prev_table,prev_table,subtree);
  }
  prev_table = mmio->radixlog.prev_table;
  PRINT("large_size = %d",large_size);
  while (large_size && subtree!=prev_table && prev_table->offset >= (unsigned long)offset && prev_table->offset + TABLE_SIZE[prev_table->type] <= (unsigned long)(offset + len)) { 
    __sync_bool_compare_and_swap(&mmio->radixlog.prev_table,prev_table,subtree);
    prev_table = mmio->radixlog.prev_table;
  }
  PRINT("table = %p bitmap = %lu bitmap_valid = %lu",table, table->bitmap[0], table->bitmap_valid[0]);
  PRINT("fsize = %ld offset = %ld ret = %ld",mmio->fsize,offset,ret); 

  blog->checksum += (tid + mmio->ino + mmio->fsize + offset + len);
  for (int i = 0; i < blog_index; i++) 
    blog->checksum += blog->bitmap[i];
  blog->len = len;
  
  if (blog_index <=2)
    FLUSH(blog,sizeof(*blog)/2);
  else
    FLUSH(blog,sizeof(*blog));
  
  FENCE();
  PRINT("mfence");
  if (mmio->fsize < offset + ret) {
    mmio->fsize = offset + ret;
    PRINT("update mmio->fsize=%lu ret = %lu", mmio->fsize,ret);
  }
  
  PRINT("blog_index = %d\n",blog_index); 
  
  PRINT("before unlock\n");
  for (int i = 0; i <= blog_index; i++) {
    PRINT("i = %d bitmap = %p start = %d, nbits = %d",i, boplog[i].bitmap,boplog[i].start,boplog[i].nbits);
    bitmap_not(boplog[i].bitmap,boplog[i].start,boplog[i].nbits);
    if (fgl) {
      if (boplog[i].type >= TABLE) {
        log_table_t* table = (log_table_t*)boplog[i].locked_entry;
        PRINT("table = %p start = %u end = %u",table,boplog[i].start,boplog[i].start + boplog[i].nbits);
        for (unsigned int j = boplog[i].start; j < boplog[i].start + boplog[i].nbits; j++) {
          PRINT("tid = %d unlock %p %d\n", tid, table, j);
          CLEAN_FULLLOCK(&(table->lock[j]));
       }
      } else if (boplog[i].type == 0){
        //unlock_entry((idx_entry_t*)boplog[i].locked_entry,boplog[i].start,boplog[i].start+boplog[i].nbits - 1,WLOCK);
      } else {
          PRINT("tid = %d unlock2 %p %d\n", tid, table,boplog[i].index);
        log_table_t* table = (log_table_t*)boplog[i].table;
        CLEAN_FULLLOCK(&(table->lock[boplog[i].index]));
      }
    }
    FLUSH(boplog[i].bitmap,sizeof(*boplog[i].bitmap));
  }
  PRINT("end write fd = %d fgl = %d\n",fd, fgl); 
  if (!fgl) {
    CLEAN_FULLLOCK(&(mmio->lock));
   }
  /*
  if (mmio->ref > 1) {
    increase_counter(&mmio->write);
    increase_size(&mmio->write_size,len);
  } else {
  */
    mmio->write++;
    mmio->write_size += len;
  //}
  blog->len = 0;
  //FLUSH(blog,sizeof(*blog));
  //FLUSH(&(blog->len),sizeof(blog->len));
  FENCE();
  
  /*
   * Release all writer-locks.
   */
  PRINT("mmio->write = %d mmio->read = %d",mmio->write,mmio->read);
  if (mmio->write == 100) {
    //int write_size = (1.0 * mmio->write_size / mmio->write);
    //int size = ceil(log(write_size)/log(2));
    //int size = ceil(log2((1.0 * mmio->write_size / mmio->write)));
    //double thres = size > 10 ? 1 - (size - 10) * 0.1 : 1; 
    if (mmio->policy_g == READOPT) { // && mmio->read == 0
      //PRINT("thres = %f", thres);
      mmio->policy_g = WRITEOPT;
      PRINT("change to write opt");
    }
  }
  bravo_read_unlock(&mmio->rwlock);
  return (ssize_t)ret;
}

static inline bool read_lock(mmio_t *mmio, bitmap_Op_log* boplog, unsigned long* boplog_index,void* locked_entry,log_table_t** prev_table, bool is_table, unsigned long off, unsigned long len,unsigned long old_off, bool finelock) {
  log_table_t* table;
  if (is_table) { 
    table = (log_table_t*)locked_entry;
    off = off % TABLE_SIZE[table->type];
    unsigned long next_size = TABLE_SIZE[table->type - 1];    
    if (len < PAGE_SIZE && table->type == TABLE) {
      off = off / next_size * next_size;
      len = PAGE_SIZE;
    }
    unsigned int left_index = off / next_size;
    unsigned int right_index = (off + len - 1) / next_size;

//    && (test_bit(table->index,table->parent->bitmap_valid) || !test_bit((*prev_table)->index,(*prev_table)->parent->bitmap_valid))
    if (left_index != right_index || (left_index == right_index && len == next_size)) {
      if ((*prev_table) != table) { // && (test_bit(table->index,table->parent->bitmap_valid) || !test_bit((*prev_table)->index,(*prev_table)->parent->bitmap_valid))
        PRINT("prev_table = %p table = %p finelock = %d",*prev_table,table, finelock);
        (*prev_table) = table;
        if (!finelock) return true;
        if (table->type != TABLE) HANDLE_ERROR("table type = %d",table->type);
      }
      PRINT("lock = %d",table->parent->lock[table->index]);
      //TODO: The ref and the clear lock
      /*
      if (bitmap_empty(table->bitmap,PTRS_PER_TABLE) && bitmap_empty(table->bitmap_valid,PTRS_PER_TABLE) && !TEST_IWLOCK(&table->parent->lock[table->index])) {
        PRINT("lock RLOCK");
        //table->parent->lock[table->index] = 0;
        lock_table(table->parent,table->index,RLOCK);
        if (boplog[*boplog_index].locked_entry) (*boplog_index)++;
        boplog[*boplog_index].locked_entry = table->parent;
        boplog[*boplog_index].start = table->index;
        boplog[*boplog_index].nbits = 1;
        boplog[*boplog_index].type = table->type + 1;
        //printf("lock table->type = %d\n",table->type);
        return true;
      }
      */
    }
    bool still_is_table = table->type > TABLE; 
    
    if (left_index == right_index && (off % next_size || (off % next_size + len) < next_size)) {
      lock_table(table,left_index,IRLOCK);
      void* next_level_table;
      if (still_is_table) 
        next_level_table = get_table_entry(table,left_index);
      else {
        next_level_table = get_page_entry(table, left_index);                 
        HANDLE_ERROR("Fine lock");
      }
      unsigned long new_len = len > next_size - off % next_size ? next_size - off % next_size : len;
      return read_lock(mmio,boplog,boplog_index,next_level_table,prev_table,still_is_table,off,new_len,old_off,finelock);
    }
    if (table->type > TABLE) HANDLE_ERROR("table->type > TABLE");
    if (off % next_size != 0) {
      read_lock(mmio,boplog,boplog_index,get_table_entry(table,left_index),prev_table,still_is_table,off,next_size - off%next_size,old_off,finelock);
      left_index++;
    }
    if (left_index < right_index || (left_index == right_index && off % next_size == 0 && (off+len)%next_size == 0)) {
      PRINT("log lock table = %p li = %u ri = %u\n",table, left_index, right_index);
      if (boplog[*boplog_index].locked_entry) (*boplog_index)++;
      boplog[*boplog_index].locked_entry = table;
      boplog[*boplog_index].start = left_index;
      boplog[*boplog_index].nbits = right_index - left_index;
      if (right_index >= left_index && (off+len)%next_size == 0) boplog[*boplog_index].nbits++;
      boplog[*boplog_index].type = table->type;
      if (boplog[*boplog_index].nbits<1)
        HANDLE_ERROR("boplog[*boplog_index].nbits = %u\n",boplog[*boplog_index].nbits);
    }
    PRINT("left_index = %u right_index = %u (off + len) mod next_size = %lu next_size = %lu",left_index,right_index,(off+len)%next_size,next_size);
    for (unsigned int i = left_index; i < right_index; i++) {
      if (table->type > TABLE)
        HANDLE_ERROR("lagre size RLock! %d",table->type);
      lock_table(table,i,RLOCK);
    }
    left_index=right_index;
    if ((off+len)%next_size == 0) {
        lock_table(table,right_index,RLOCK);
        PRINT("read lock table %p index = %u mode = %d lock = %d end\n",table, left_index, RLOCK, table->lock[right_index]);
        left_index++;
    }
    if (right_index >= left_index) {
      PRINT("third case");
      if ((off + len) % next_size) {
        unsigned long new_off = (off + len) / next_size * next_size;
        void* next_level_table;
        if (still_is_table) 
          next_level_table = get_table_entry(table,left_index);
        else {
          next_level_table = get_page_entry(table, left_index);   
          HANDLE_ERROR("Fine lock");
        }
        if (read_lock(mmio,boplog,boplog_index,next_level_table,prev_table,still_is_table,new_off, off + len - new_off,old_off,finelock))
          return true;
      }
    }
  } else {
    PRINT("lock_entry end %lu",*boplog_index);
  }
  PRINT("read lock end");
  return false;
} 

/*
  TODO: dst of prev_table 
*/
ssize_t mmio_read_mgl(mmio_t *mmio, int fd, off_t offset, void *buf, size_t len) {
  /*
   * Acquire the reader-locks of the mmio.
   */
  bravo_read_lock(&mmio->rwlock);
  /*
   * Check the file size to see if the requested read is possible.
   */
  if (check_fsize(mmio, offset, len)) {
    PRINT("the requested length %ld + %lu exceeds the file size %ld.",
          offset,len,mmio->fsize);
    len = mmio->fsize > offset ? mmio->fsize - offset : 0;
    PRINT("the reset length = %lu",len);
    if (len == 0) {
      PRINT("Empty file, return");
      bravo_read_unlock(&mmio->rwlock);
      return 0;
    }
  }
  /*
   * Perform the read
   */                     
  PRINT("mmio_read_mgl start fd = %d", fd);
  bitmap_Op_log boplog[MAX_BITMAP_NUMBER];
  log_table_t *prev_table, *old_prev = NULL;
  unsigned long boplog_index = 0;
  bool finelock = (mmio->policy_l == FINELOCK),readopt = (mmio->policy_g == READOPT);
  if (!finelock) {
    PRINT("read lock start mmio->lock = %d", mmio->lock);
    SET_READLOCK(&mmio->lock);
  } else {
    while (mmio->lock) PRINT("lock = %d\n");
    for (int i = 0; i < MAX_BITMAP_NUMBER; i++) boplog[i].locked_entry = NULL;
  }
  if (!readopt || finelock) {
    prev_table = mmio->radixlog.prev_table;
    old_prev = prev_table;
    PRINT("fd = %d prev_table = %p prev_table->type = %d",fd, prev_table, prev_table->type);
    if (prev_table->offset <= (unsigned long)offset && prev_table->offset + TABLE_SIZE[prev_table->type] >= (unsigned long)(offset + len)) {
      PRINT("use prev_table offset = %d", offset);
      if (finelock)read_lock(mmio,boplog,&boplog_index,(void*)prev_table,&prev_table,true,offset%TABLE_SIZE[prev_table->type],len,offset, finelock);                                                                                              
    } else {
      if (prev_table->index!=63 && prev_table->offset + TABLE_SIZE[prev_table->type] <= (unsigned long)offset && prev_table->offset + 2 * TABLE_SIZE[prev_table->type] >= (unsigned long)(offset + len)) {
        log_table_t* next = get_table_entry(prev_table->parent,prev_table->index + 1);
        if (finelock) lock_table(next->parent,next->index,IRLOCK);
        prev_table = next;
        if (finelock) read_lock(mmio,boplog,&boplog_index,(void*)prev_table,&prev_table,true,offset%TABLE_SIZE[prev_table->type],len,offset,finelock);     
     } else {
        PRINT("research old prev_table = %p prev_table->type = %d finelock = %d",prev_table, prev_table->type, finelock);
        read_lock(mmio,boplog,&boplog_index,(void*)mmio->radixlog.skip,&prev_table,true,offset,len,offset,finelock);
        PRINT("new prev_table = %p prev_table->type = %d prev_table->offset = %d",prev_table, prev_table->type, prev_table->offset);
      }
    }
  }

  void *dst = (void *)buf, *src;
  off_t off = offset, src_offset;
  size_t ret = 0;
  //if (bitmap_empty(prev_table->bitmap,PTRS_PER_TABLE) && bitmap_empty(prev_table->bitmap_valid,PTRS_PER_TABLE)) {
  if (readopt) {
    PRINT("memcpy(%p,%p,%lu)",buf,mmio->start + offset, len);
    memcpy(buf,mmio->start + offset, len);
    ret = len;
    PRINT("len = %d ret = %d",len, ret);
  }
  unsigned long index, log_offset, log_len;     
  log_table_t *table;
  log_size_t log_size;
  PRINT("Begin read offset = %d fd = %d\n", offset, fd); 
  PRINT("prev_table->type = %d table->index = %d table->parent = %p",prev_table->type, prev_table->index, prev_table->parent);
  while (len > ret) {    
    src = mmio->start;   
    src_offset = off;   
    table = prev_table;
    //table = mmio->radixlog.skip;
    PRINT("off = %ld, table->type = %d index = %d first = %d second = %d",off, table->type, (off >> LMD_SHIFT)&(PTRS_PER_TABLE - 1), (off >> LMD_SHIFT), PTRS_PER_TABLE - 1);
    index = get_table_index(off,table->type);
    PRINT("table = %p index = %d test bit bitmap = %d test valid = %d",table, index, test_bit(index, table->bitmap),test_bit(index, table->bitmap_valid));
    while (table->type > TABLE && (test_bit(index,table->bitmap) || test_bit(index,table->bitmap_valid))) {
      GET_NEXT_LEVEL_TABLE(table,off);     
      if (table->log != NULL && test_bit(table->index,table->parent->bitmap_valid)) {
        src_offset = off & (TABLE_SIZE[table->type] - 1);
        src = table->log;
      }
      index = get_table_index(off,table->type);
    }
    PRINT("table = %p table->type = %d table->index = %d",table, table->type, table->index);
    if (table->type > LMD && src != mmio->start)
      HANDLE_ERROR("Larger Read! table->type = %d",table->type);     
    log_size = TABLE_SIZE[NEXT_TABLE_TYPE(table->type)];
    if (table->type > TABLE || (table->type == TABLE && !((test_bit(index,table->bitmap) || test_bit(index,table->bitmap_valid))))) {
      unsigned long log_index1 = find_first_bit_from_index(table->bitmap,PTRS_PER_TABLE,index);
      unsigned long log_index2 = find_first_bit_from_index(table->bitmap_valid,PTRS_PER_TABLE,index);
      unsigned long log_index = log_index1 > log_index2 ? log_index2 : log_index1;
      PRINT("index = %lu, log_index = %lu src_offset = %lu len - ret = %lu",index, log_index, src_offset, len-ret);
      log_len = (len - ret) > (log_index - index) * log_size ? (log_index - index) * log_size : (len - ret); 
      memcpy(dst, src + src_offset, log_len);
      PRINT("memcpy(%p,%p,%lu)",dst, src + src_offset, log_len);
    } else {      
      log_offset = off & (log_size - 1);
      log_len = log_size - log_offset > (len - ret) ? (len - ret) : log_size - log_offset;
      PRINT("log_offset = %lu log_len = %lu", log_offset, log_len); 
      void* log_;
      PRINT("index = %lu",index);
      idx_entry_t* log_entry = get_page_entry(table,index);
      log_ = log_entry->log;
      PRINT("index = %lu bitmap seted = %d valid bitmap seted = %d",index,test_bit(index,table->bitmap),test_bit(index,table->bitmap_valid));
      if (test_bit(index,table->bitmap)) {
        int left_index = log_offset / MIN_SIZE;
        int right_index = (log_offset + log_len - 1) / MIN_SIZE;
        unsigned int left_offset = log_offset % MIN_SIZE, right_offset = (log_offset + log_len) % MIN_SIZE, len, next;
        unsigned long bitmap;
        unsigned long dst_offset = 0;
        
        PRINT("left_index = %d right_index = %d left_offset = %u right_offset= %u", left_index, right_index, left_offset, right_offset); 
        PRINT("bitmap = %p",log_entry->bitmap);
        if (test_bit(left_index,log_entry->bitmap)) {
          PRINT("bit seted");
          if (left_index == right_index) {
            memcpy(dst, log_ + log_offset, log_len);
            PRINT("memcpy(%p,%p,%lu)",dst, log_ + log_offset, log_len);
          } else {
            if (left_offset != 0) {
              PRINT("memcpy(%p,%p,%lu)",dst, log_ + log_offset, MIN_SIZE - left_offset);  
              memcpy(dst, log_ + log_offset, MIN_SIZE - left_offset);  
            } 
          }
        } else {
          PRINT("bit not seted");
          if (left_index == right_index) {
            memcpy(dst, src + src_offset, log_len);
            PRINT("memcpy(%p,%p,%lu)",dst, src + src_offset, log_len);
          }
          else {
            if (left_offset != 0) {
              PRINT("memcpy(%p,%p,%lu)",dst, src + src_offset, MIN_SIZE - left_offset);
              memcpy(dst, src + src_offset, MIN_SIZE - left_offset);
            }
          }
        }

        if (left_index != right_index && right_offset != 0) {
          if (test_bit(right_index,log_entry->bitmap)) {
              PRINT("bit seted");
              PRINT("memcpy(%p,%p,%lu)",dst + log_len - right_offset, log_ + log_offset + log_len - right_offset, right_offset);  
              memcpy(dst + log_len - right_offset, log_ + log_offset + log_len - right_offset, right_offset);  
          } else {
              PRINT("bit not seted");
              PRINT("memcpy(%p,%p,%lu)",dst + log_len - right_offset, src + src_offset + log_len - right_offset, right_offset);
              memcpy(dst + log_len - right_offset, src + src_offset + log_len - right_offset, right_offset);
          }
        }

        if (left_index == right_index) 
          left_index++;
        if (left_offset != 0) {
            left_index++;        
            dst_offset += (MIN_SIZE - left_offset);
            log_offset += (MIN_SIZE - left_offset);
            src_offset += (MIN_SIZE - left_offset); 
          }
        if (right_offset != 0)
          right_index--;

        while (left_index <= right_index) {
          if (test_bit(left_index,log_entry->bitmap)) {
            PRINT("bit seted"); 
            bitmap = ~(~0UL >> (BITS_PER_LONG - left_index - 1) | log_entry->bitmap[0]);
            next = __ffs(bitmap);
            next = (next > (unsigned long)right_index + 1 || next == 0 || next == 63) ? (unsigned long)right_index + 1 : next;
            len = next - left_index;
            memcpy(dst + dst_offset, log_ + log_offset, len * MIN_SIZE);
            PRINT("memcpy(%p,%p,%u)",dst + dst_offset, log_ + log_offset, len * MIN_SIZE);
          } else {
            PRINT("bit not seted");
            bitmap = ~0UL << left_index & log_entry->bitmap[0];
            next = __ffs(bitmap);
            next = (next > (unsigned long)right_index + 1 || next == 0 || next == 63) ? (unsigned long)right_index + 1 : next;
            len = next - left_index;
            memcpy(dst + dst_offset, src + src_offset, len * MIN_SIZE);
            PRINT("memcpy(%p,%p,%u)",dst + dst_offset, src + src_offset, len * MIN_SIZE);
          }
          dst_offset += len * MIN_SIZE;
          log_offset += len * MIN_SIZE;     
          src_offset += len * MIN_SIZE;     
          left_index = next;
        }
      } else {
        memcpy(dst, log_ + log_offset, log_len);
        PRINT("memcpy(%p,%p,%lu)",dst,  log_ + log_offset, log_len);
      }
    }
    PRINT("Read %lu from %ld",log_len,off); 
    ret += log_len;
    off += log_len;
    dst += log_len;
  }
  /*
  if (mmio->ref > 1) {
    increase_counter(&mmio->read);
    increase_size(&mmio->read_size,len);
  } else {
  */
    mmio->read++;
    mmio->read_size += len;
  //}
  if (!finelock) {
    PRINT("read unlock start mmio->lock = %d", mmio->lock);
    CLEAN_READLOCK(&mmio->lock);
    PRINT("unlock done");
  } else {
    if (old_prev!=NULL && old_prev!=prev_table)
      __sync_bool_compare_and_swap(&mmio->radixlog.prev_table,old_prev,prev_table);
    PRINT("boplog_index  = %d\n",boplog_index);
    for (unsigned long i = 0; i <= boplog_index; i++) {
      PRINT("i = %ld start = %d, nbits = %d",i, boplog[i].start,boplog[i].nbits);
      log_table_t* table = (log_table_t*)(boplog[i].locked_entry);
      PRINT("table = %p start = %u end = %u",table,boplog[i].start,boplog[i].start + boplog[i].nbits);
      if (boplog[i].type >= TABLE) {
        for (unsigned int j = boplog[i].start; j < boplog[i].start + boplog[i].nbits; j++) {
          CLEAN_READLOCK(&(table->lock[j]));
        }
      } else  {
        CLEAN_READLOCK(&(table->lock[boplog[i].start]));
      }
    }
    if (mmio->ref == 1)
      mmio->policy_l = FILELOCK;
  }  
 /*
   * Release the reader-lock of the mmio.
   */
  bravo_read_unlock(&mmio->rwlock);
  
  return len;
}