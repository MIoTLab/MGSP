#ifndef LIBNVMMIO_CONFIG_H
#define LIBNVMMIO_CONFIG_H

#define DEFAULT_PMEM_PATH "/mnt/pmem"
#define MAX_FD 512
#define FILE_HASH_SIZE MAX_FD
#define NR_MMIOS (MAX_FD << 1)
#define BASIC_MMAP_SIZE (1UL << 26) /* 64MB */
#define LOG_FILE_SIZE (1UL << 32)   /* 4GB */
#define NR_ALLOC_TABLES (1UL << 19)
#define NR_NODE_FILL 512
#define NR_MMIO_FILL 50
#define DEFAULT_MMAP_SIZE (1 << (PAGE_SHIFT + BITS_PER_LEVEL)) /* 2MB */
#define HYBRID_WRITE_RATIO (40)
#define SYNC_PERIOD (1000000000000)
#define MAX_SKIP_NODES (2L)
#define HYBRID_LOGGING true
#define BMAP_SIZE 32

#if 0
#define DEFAULT_POLICY UNDO
#else
#define DEFAULT_POLICY REDO
#define DEFAULT_RW_POLICY READOPT
#define DEFAULT_LOCK_POLICY FILELOCK
#endif

typedef enum log_size_enum {
  LOG_4K,
  LOG_8K,
  LOG_16K,
  LOG_32K,
  LOG_64K,
  LOG_128K,
  LOG_256K,
  LOG_512K,
  LOG_1M,
  LOG_2M,
  NR_LOG_SIZES
} log_size_t;


#endif /* LIBNVMMIO_CONFIG_H */
