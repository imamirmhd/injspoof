#ifndef INJSPOOF_POOL_H
#define INJSPOOF_POOL_H

#include <stddef.h>
#include <stdint.h>

/*
 * Lock-free fixed-size memory pool.
 * Pre-allocates a contiguous block of buffers to avoid malloc/free
 * on the hot path. Uses atomic operations for thread safety.
 */

#define POOL_DEFAULT_COUNT   4096
#define POOL_DEFAULT_BUFSIZE 2048

typedef struct {
    uint8_t  *block;          /* contiguous memory block */
    uint32_t *free_stack;     /* stack of free buffer indices */
    _Atomic uint32_t top;     /* stack top (atomic for lock-free ops) */
    uint32_t  count;          /* total number of buffers */
    uint32_t  buf_size;       /* size of each buffer */
} pool_t;

/* Initialize pool with `count` buffers of `buf_size` bytes each.
 * Returns 0 on success, -1 on failure. */
int  pool_init(pool_t *pool, uint32_t count, uint32_t buf_size);

/* Allocate a buffer from the pool. Returns NULL if exhausted. */
void *pool_alloc(pool_t *pool);

/* Return a buffer to the pool. */
void pool_free(pool_t *pool, void *ptr);

/* Destroy the pool and release all memory. */
void pool_destroy(pool_t *pool);

/* Get number of available buffers. */
uint32_t pool_available(pool_t *pool);

#endif /* INJSPOOF_POOL_H */
