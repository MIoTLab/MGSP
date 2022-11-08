#include "radixlog.h"

#include <limits.h>
#include <stdbool.h>

#include "allocator.h"
#include "config.h"
#include "debug.h"
#include "slist.h"

inline bool check_prev_table(unsigned long prev_table_index,
                             unsigned long offset) {
  if (prev_table_index == ((offset >> LMD_SHIFT) & TABLE_MASK)) {
    return true;
  }
  return false;
}

static inline void atomic_increase(int *count) {
  int old, new;

  do {
    old = *count;
    new = old + 1;
  } while (!__sync_bool_compare_and_swap(count, old, new));
}

inline table_type_t get_deepest_table_type(unsigned long maxoff) {
  if (maxoff >> LMD_SHIFT) {
    PRINT("%lu >> LMD_SHIFT = %lu", maxoff, maxoff >> LMD_SHIFT);
    if (maxoff >> LUD_SHIFT) {
      PRINT("%lu >> LUD_SHIFT = %lu", maxoff, maxoff >> LUD_SHIFT);
      if (maxoff >> LGD_SHIFT) {
        PRINT("%lu >> LGD_SHIFT = %lu", maxoff, maxoff >> LGD_SHIFT);
        PRINT("LGD");
        return LGD;
      }
      PRINT("LUD");
      return LUD;
    }
    PRINT("LMD");
    return LMD;
  }
  PRINT("TABLE");
  return TABLE;
}

void init_radixlog(radix_root_t *root, unsigned long filesize) {
  table_type_t deepest_table_type, type;
  log_table_t *parent, *table;
  unsigned long index, maxoff;

  deepest_table_type = get_deepest_table_type(filesize - 1);
  PRINT("filesize = %lu, deepest_table_tpye = %u", filesize, deepest_table_type);
  maxoff = filesize - 1;
  type = LGD;
  parent = NULL;

  do {
    table = alloc_log_table(type);
    table->offset = 0;
    if (parent != NULL) {
      switch (type) {
        case LUD:
          index = LGD_INDEX(maxoff);
          break;
        case LMD:
          index = LUD_INDEX(maxoff);
          break;
        case TABLE:
          index = LMD_INDEX(maxoff);
          break;
        default:
          HANDLE_ERROR("wrong table type");
      }
      parent->entries[index] = table;
      table->parent = parent;
      table->index = index;
      FLUSH(&parent->entries[index],sizeof(table));
    } else {
      root->lgd = table;
    }
    parent = table;
    type = NEXT_TABLE_TYPE(type);
  } while (type >= deepest_table_type);
  PRINT("skip = %p type = %d filesize = %lu",table, table->type, filesize);
  root->skip = table;
  root->prev_table = root->skip;
  root->prev_table_index = ULONG_MAX;
}

log_table_t *find_log_table(radix_root_t *root, unsigned long offset) {
  log_table_t *lgd, *lud, *lmd, *table = NULL;
  unsigned long index;

  if (root->skip) {
    switch (root->skip->type) {
      case TABLE:
        PRINT("skip to TABLE");
        table = root->skip;
        break;

      case LMD:
        PRINT("skip to LMD");
        lmd = root->skip;

        index = LMD_INDEX(offset);
        PRINT("LMD index=%lu", index);
        table = lmd->entries[index];

        if (table == NULL) {
          return NULL;
        }
        break;

      case LUD:
        PRINT("skip to LUD");
        lud = root->skip;

        index = LUD_INDEX(offset);
        PRINT("LUD index=%lu", index);
        lmd = lud->entries[index];

        if (lmd == NULL) {
          return NULL;
        }

        index = LMD_INDEX(offset);
        PRINT("LMD index=%lu", index);
        table = lmd->entries[index];

        if (table == NULL) {
          return NULL;
        }
        break;

      case LGD:
        PRINT("skip to LGD");
        lgd = root->skip;

        index = LGD_INDEX(offset);
        PRINT("LGD index=%lu", index);
        lud = lgd->entries[index];

        if (lud == NULL) {
          return NULL;
        }

        index = LUD_INDEX(offset);
        PRINT("LUD index=%lu", index);
        lmd = lud->entries[index];

        if (lmd == NULL) {
          return NULL;
        }

        index = LMD_INDEX(offset);
        PRINT("LMD index=%lu", index);
        table = lmd->entries[index];

        if (table == NULL) {
          return NULL;
        }
        break;

      default:
        HANDLE_ERROR("wrong table type");
        break;
    }
  }
  return table;
}

log_table_t *get_log_table(radix_root_t *root, unsigned long offset) {
  log_table_t *lgd, *lud, *lmd, *table;
  unsigned long index;

  if (check_prev_table(root->prev_table_index, offset)) {
    PRINT("reuse the previous table: prev=%lx, current=%lx",
          root->prev_table_index, offset);
    return root->prev_table;
  }
  PRINT("%d prev_table = %d, table = %d",root->skip->type,root->prev_table,root->skip);
  switch (root->skip->type) {
    case TABLE:
      PRINT("skip to TABLE");
      table = root->skip;
      break;

    case LMD:
      PRINT("skip to LMD");
      lmd = root->skip;

      index = LMD_INDEX(offset);
      PRINT("LMD index=%lu", index);
      table = lmd->entries[index];

      if (table == NULL) {
        ALLOC_TABLE(table, TABLE, lmd, index);
      }
      break;

    case LUD:
      PRINT("skip to LUD");
      lud = root->skip; 

      index = LUD_INDEX(offset);
      PRINT("LUD index=%lu", index);
      lmd = lud->entries[index];

      if (lmd == NULL) {
        ALLOC_TABLE(lmd, LMD, lud, index);
      }

      index = LMD_INDEX(offset);
      PRINT("LMD index=%lu", index);
      table = lmd->entries[index];

      if (table == NULL) {
        ALLOC_TABLE(table, TABLE, lmd, index);
      }
      break;

    case LGD:
      PRINT("skip to LGD");
      lgd = root->skip;

      
      index = LGD_INDEX(offset);
      PRINT("LGD index=%lu", index);
      lud = lgd->entries[index];

      if (lud == NULL) {
        ALLOC_TABLE(lud, LUD, lgd, index);
      }
      index = LUD_INDEX(offset);
      PRINT("LUD index=%lu", index);
      lmd = lud->entries[index];

      if (lmd == NULL) {
        ALLOC_TABLE(lmd, LMD, lud, index);
      }
      index = LMD_INDEX(offset);
      PRINT("LMD index=%lu", index);
      table = lmd->entries[index];

      if (table == NULL) {
        ALLOC_TABLE(table, TABLE, lmd, index);
      }
      break;

    default:
      HANDLE_ERROR("wrong table type");
      break;
  }
  PRINT("%d prev_table = %d, table = %d",TABLE_MASK & (offset >> LMD_SHIFT),root->prev_table,table);
  root->prev_table = table;
  root->prev_table_index = TABLE_MASK & (offset >> LMD_SHIFT);
  return table;
}

inline log_size_t set_log_size(unsigned long offset, size_t len) {
  log_size_t log_size = LOG_4K;
  log_size_t max_log_size = NR_LOG_SIZES - 1;

  len += offset & (LOG_SIZE(log_size) - 1);
  len = (len - 1) >> LOG_SHIFT(log_size);

  while (len && log_size < max_log_size) {
    len = len >> 1;
    log_size++;
  }
  return LOG_4K;
}

inline log_table_t *get_table_entry(log_table_t *table,unsigned long index) {
  log_table_t * next_level_table_ = table->entries[index];                        
  if (next_level_table_ == NULL) {                       
    PRINT("ALLOC_TABLE\n");
    ALLOC_TABLE(next_level_table_, NEXT_TABLE_TYPE(table->type), table, index);               
    PRINT("ALLOC_TABLE end\n");
  }
  table->entries[index] = next_level_table_;
  FLUSH(&table->entries[index],sizeof(table->entries[index]));
  return next_level_table_;
}

inline idx_entry_t *get_page_entry(log_table_t *table,unsigned long index) {
  idx_entry_t *entry;
  
  entry = table->entries[index];
  if (entry == NULL) {
    entry = alloc_idx_entry(LOG_4K);
    bitmap_zero(entry->bitmap,PAGE_SIZE / MIN_SIZE);
    if (!__sync_bool_compare_and_swap(&table->entries[index], NULL, entry)) {
      free_idx_entry(entry, LOG_4K);
      entry = table->entries[index];
    }
    table->entries[index] = entry;
    FLUSH(&table->entries[index],sizeof(table->entries[index]));
  }
  return entry;
}

inline idx_entry_t *get_log_entry(unsigned long epoch, log_table_t *table,
                                  unsigned long index, log_size_t log_size) {
  idx_entry_t *entry;

  entry = table->entries[index];

  if (entry == NULL) {
    entry = alloc_idx_entry(log_size);
    entry->epoch = epoch;

    if (!__sync_bool_compare_and_swap(&table->entries[index], NULL, entry)) {
      free_idx_entry(entry, log_size);
      entry = table->entries[index];
    }
  }

  return entry;
}

inline unsigned long get_table_index(unsigned long offset, table_type_t type) {
  switch (type) {
    case TABLE:  
      return TABLE_INDEX(LOG_4K,offset);
    case LMD:
      return LMD_INDEX(offset);
    case LUD:
      return LUD_INDEX(offset);
    case LGD:
      return LGD_INDEX(offset);
    default:
      return 0;
  }
}
