#ifndef INJSPOOF_LOG_H
#define INJSPOOF_LOG_H

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>

/* Runtime log levels */
#define LOG_LEVEL_ERROR  0
#define LOG_LEVEL_WARN   1
#define LOG_LEVEL_INFO   2
#define LOG_LEVEL_DEBUG  3

/* Global runtime log level (set by config, defaults to INFO) */
extern int g_log_level;

/* Strip path prefix, keep only filename */
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define LOG_ERROR(fmt, ...) do { \
    if (g_log_level >= LOG_LEVEL_ERROR) \
        fprintf(stderr, "[ERR] %s:%d: " fmt "\n", __FILENAME__, __LINE__, ##__VA_ARGS__); \
} while(0)

#define LOG_WARN(fmt, ...) do { \
    if (g_log_level >= LOG_LEVEL_WARN) \
        fprintf(stderr, "[WRN] %s:%d: " fmt "\n", __FILENAME__, __LINE__, ##__VA_ARGS__); \
} while(0)

#define LOG_INFO(fmt, ...) do { \
    if (g_log_level >= LOG_LEVEL_INFO) \
        fprintf(stderr, "[INF] " fmt "\n", ##__VA_ARGS__); \
} while(0)

#ifdef DEBUG
#define LOG_DEBUG(fmt, ...) do { \
    if (g_log_level >= LOG_LEVEL_DEBUG) \
        fprintf(stderr, "[DBG] %s:%d: " fmt "\n", __FILENAME__, __LINE__, ##__VA_ARGS__); \
} while(0)
#else
#define LOG_DEBUG(fmt, ...) do { (void)0; } while(0)
#endif

#define LOG_PERROR(msg) \
    LOG_ERROR("%s: %s", msg, strerror(errno))

#endif /* INJSPOOF_LOG_H */
