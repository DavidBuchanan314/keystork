// The payload keystorkd loads into a target app.
//
// C rather than C++, and deliberately: this gets dlopen'd into somebody else's
// process, so it should drag in nothing but libc and liblog. It is embedded in
// the daemon's .rodata and written into the target through a memfd, so it
// never exists as a file anywhere.
//
// At this stage it does one thing: prove it ran before the app did, then stop
// the process so that nothing of the app's ever runs at all.
//
// The proof is `cmdline`. keystorkd catches the process at the setresuid in
// the zygote's specialization, which is before Process.setArgV0 renames it --
// and that rename is itself before ActivityThread.main. So a log line still
// reading "zygote64" is positive evidence of having run earlier than the
// earliest point any of the app's own code could execute, which is a much
// better claim than "we did not see the app's logs".

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <android/log.h>

#define TAG "keystork-agent"

// /proc files that read as a single short line, or as NUL-separated fields in
// the case of cmdline. Everything after the first NUL is dropped, which for
// cmdline leaves argv[0], the part that gets renamed.
static void ReadProcLine(const char* path, char* out, size_t size) {
  out[0] = '\0';
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    snprintf(out, size, "<%s: %s>", path, strerror(errno));
    return;
  }
  ssize_t got = read(fd, out, size - 1);
  close(fd);
  if (got < 0) got = 0;
  out[got] = '\0';
  char* newline = strchr(out, '\n');
  if (newline != NULL) *newline = '\0';
}

static int CountThreads(void) {
  DIR* tasks = opendir("/proc/self/task");
  if (tasks == NULL) return -1;
  int count = 0;
  for (struct dirent* entry = readdir(tasks); entry != NULL; entry = readdir(tasks)) {
    if (entry->d_name[0] != '.') count++;
  }
  closedir(tasks);
  return count;
}

__attribute__((constructor)) static void KeystorkAgentMain(void) {
  char cmdline[256];
  char context[256];
  ReadProcLine("/proc/self/cmdline", cmdline, sizeof(cmdline));
  ReadProcLine("/proc/self/attr/current", context, sizeof(context));

  __android_log_print(ANDROID_LOG_INFO, TAG,
                      "loaded: pid=%d tid=%d uid=%d gid=%d threads=%d", getpid(), gettid(),
                      getuid(), getgid(), CountThreads());
  __android_log_print(ANDROID_LOG_INFO, TAG, "cmdline=%s selinux=%s", cmdline, context);
  __android_log_print(ANDROID_LOG_INFO, TAG,
                      "stopping the process here; none of the app's code has run");

  // Not exit(): that would run atexit handlers and static destructors
  // belonging to a process we are in the middle of hijacking. This also means
  // dlopen never returns, which is why the injector treats a tracee that
  // exited during the call as the expected outcome rather than a failure.
  _exit(0);
}
