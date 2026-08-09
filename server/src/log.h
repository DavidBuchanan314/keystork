#pragma once

#include <cstdio>
#include <unistd.h>

// Minimal stderr logging. The daemon is launched by hand from a root shell, so
// stderr is where the operator is already looking; there is no logcat plumbing
// and deliberately no log file.

#define KS_LOG(level, fmt, ...) \
  ::fprintf(stderr, "[keystorkd:%d] " level ": " fmt "\n", static_cast<int>(::getpid()), ##__VA_ARGS__)

#define KS_LOGI(fmt, ...) KS_LOG("info", fmt, ##__VA_ARGS__)
#define KS_LOGE(fmt, ...) KS_LOG("error", fmt, ##__VA_ARGS__)
