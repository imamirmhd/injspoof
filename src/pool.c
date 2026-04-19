#include "pool.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

int pool_init(pool_t *pool, uint32_t count, uint32_t buf_size)
{
    if (!pool || count == 0 || buf_size == 0)
        return -1;

    pool->count    = count;
    pool->buf_size = buf_size;

    /* Allocate contiguous buffer block (cache-line aligned) */
    pool->block = (uint8_t *)aligned_alloc(64, (size_t)count * buf_size);
    if (!pool->block) {
        LOG_PERROR("pool: aligned_alloc block");
        return -1;
    }

    /* Allocate free index stack */
    pool->free_stack = (uint32_t *)malloc((size_t)count * sizeof(uint32_t));
    if (!pool->free_stack) {
        LOG_PERROR("pool: malloc free_stack");
        free(pool->block);
        pool->block = NULL;
        return -1;
    }

    /* Fill stack: all buffers start as free */
    for (uint32_t i = 0; i < count; i++) {
        pool->free_stack[i] = i;
    }

    atomic_store(&pool->top, count);

    LOG_INFO("pool: initialized %u buffers × %u bytes = %zu KB",
             count, buf_size, ((size_t)count * buf_size) / 1024);
    return 0;
}

void *pool_alloc(pool_t *pool)
{
    uint32_t cur_top, new_top, idx;

    do {
        cur_top = atomic_load_explicit(&pool->top, memory_order_acquire);
        if (cur_top == 0) {
            LOG_WARN("pool: exhausted, all %u buffers in use", pool->count);
            return NULL;
        }
        new_top = cur_top - 1;
    } while (!atomic_compare_exchange_weak_explicit(
        &pool->top, &cur_top, new_top,
        memory_order_acq_rel, memory_order_acquire));

    idx = pool->free_stack[new_top];
    return pool->block + ((size_t)idx * pool->buf_size);
}

void pool_free(pool_t *pool, void *ptr)
{
    if (!ptr || !pool || !pool->block)
        return;

    uint8_t *p = (uint8_t *)ptr;

    /* Validate pointer belongs to our block */
    if (p < pool->block || p >= pool->block + ((size_t)pool->count * pool->buf_size)) {
        LOG_ERROR("pool: attempted to free pointer outside pool range");
        return;
    }

    size_t offset = (size_t)(p - pool->block);
    if (offset % pool->buf_size != 0) {
        LOG_ERROR("pool: attempted to free misaligned pointer");
        return;
    }

    uint32_t idx = (uint32_t)(offset / pool->buf_size);
    uint32_t cur_top, new_top;

    do {
        cur_top = atomic_load_explicit(&pool->top, memory_order_acquire);
        if (cur_top >= pool->count) {
            LOG_ERROR("pool: double free detected");
            return;
        }
        new_top = cur_top + 1;
    } while (!atomic_compare_exchange_weak_explicit(
        &pool->top, &cur_top, new_top,
        memory_order_acq_rel, memory_order_acquire));

    /*
     * Write the freed index AFTER the CAS succeeds.
     * The slot at cur_top is now exclusively ours (we incremented top past it).
     * This fixes the previous race where the write happened before CAS confirmation.
     */
    pool->free_stack[cur_top] = idx;
}

void pool_destroy(pool_t *pool)
{
    if (!pool)
        return;

    free(pool->block);
    free(pool->free_stack);
    pool->block      = NULL;
    pool->free_stack  = NULL;
    pool->count       = 0;
    pool->buf_size    = 0;
    atomic_store(&pool->top, 0);

    LOG_INFO("pool: destroyed");
}

uint32_t pool_available(pool_t *pool)
{
    return atomic_load_explicit(&pool->top, memory_order_relaxed);
}
