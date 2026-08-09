#pragma once

#include <cstdio>
#include <unistd.h>

#include <android/log.h>

// Logs to stderr, where an operator who launched the daemon by hand is already
// looking, and to logcat, which is the only place left once --daemonize has
// closed that terminal. Deliberately no log file.
//
//   adb logcat -s keystorkd

#define KS_LOG(priority, level, fmt, ...)                                                    \
  do {                                                                                       \
    ::fprintf(stderr, "[keystorkd:%d] " level ": " fmt "\n", static_cast<int>(::getpid()),    \
              ##__VA_ARGS__);                                                                \
    __android_log_print(priority, "keystorkd", fmt, ##__VA_ARGS__);                           \
  } while (0)

#define KS_LOGI(fmt, ...) KS_LOG(ANDROID_LOG_INFO, "info", fmt, ##__VA_ARGS__)
#define KS_LOGE(fmt, ...) KS_LOG(ANDROID_LOG_ERROR, "error", fmt, ##__VA_ARGS__)
