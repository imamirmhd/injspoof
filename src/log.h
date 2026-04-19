#ifndef INJSPOOF_LOG_H
#define INJSPOOF_LOG_H

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>

/* Strip path prefix, keep only filename */
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define LOG_ERROR(fmt, ...) \
    fprintf(stderr, "[ERR] %s:%d: " fmt "\n", __FILENAME__, __LINE__, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
    fprintf(stderr, "[WRN] %s:%d: " fmt "\n", __FILENAME__, __LINE__, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
    fprintf(stderr, "[INF] " fmt "\n", ##__VA_ARGS__)

#ifdef DEBUG
#define LOG_DEBUG(fmt, ...) \
    fprintf(stderr, "[DBG] %s:%d: " fmt "\n", __FILENAME__, __LINE__, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) do { (void)0; } while(0)
#endif

#define LOG_PERROR(msg) \
    LOG_ERROR("%s: %s", msg, strerror(errno))

#endif /* INJSPOOF_LOG_H */
