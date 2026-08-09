// The payload keystorkd loads into a target app.
//
// C rather than C++, and deliberately: this gets dlopen'd into somebody else's
// process, so it should drag in nothing but libc and liblog. It is embedded in
// the daemon's .rodata and written into the target through a memfd, so it
// never exists as a file anywhere.
//
// Two entry points, called at two different moments:
//
//   the constructor, at the setresuid in the zygote's specialization. Far too
//   early to touch the runtime -- ART has not yet been told it is no longer a
//   zygote -- so it does nothing but prove it ran, and returns.
//
//   keystork_arm, called by the injector once the runtime has settled.
//   Everything that needs a working VM belongs here.
//
//   keystork_bind, called repeatedly while the main thread runs up to
//   ActivityThread.handleBindApplication. It answers "not yet" until the app's
//   bind data is reachable, and then takes the app's own code off every
//   classpath in the process.
//
// None of them runs on a thread of its own. The injector calls each with the
// process stopped under ptrace and waits for it to return, so nothing here
// ever races the app's startup.

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <android/log.h>
#include <jni.h>

#define TAG "keystork-agent"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define EXPORT __attribute__((visibility("default")))

// The Java half, put here by cmake/embed_blob.cmake. Read-only .rodata, which
// is all ART needs -- a dex inside an APK is mapped read-only too.
extern const char kKeystorkDexStart[];
extern const char kKeystorkDexEnd[];

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

// ---------------------------------------------------------------------------
// Stage one: loaded
//
// The proof is `cmdline`. The injector catches the process at the setresuid in
// the zygote's specialization, which is before Process.setArgV0 renames it --
// and that rename is itself before ActivityThread.main. So a log line still
// reading "zygote64" is positive evidence of having run earlier than the
// earliest point any of the app's own code could execute.
// ---------------------------------------------------------------------------

__attribute__((constructor)) static void KeystorkAgentLoaded(void) {
  char cmdline[256];
  char context[256];
  ReadProcLine("/proc/self/cmdline", cmdline, sizeof(cmdline));
  ReadProcLine("/proc/self/attr/current", context, sizeof(context));

  LOG("loaded: pid=%d tid=%d uid=%d gid=%d threads=%d", getpid(), gettid(), getuid(), getgid(),
      CountThreads());
  LOG("cmdline=%s selinux=%s", cmdline, context);
  LOG("returning; nothing here can touch the runtime yet");
}

// ---------------------------------------------------------------------------
// Stage two: armed
// ---------------------------------------------------------------------------

typedef jint (*GetCreatedJavaVMsFn)(JavaVM**, jsize, jsize*);

// The JNI Invocation API is not something an app normally reaches for, so
// which library exports it varies by release. Tried in order of least
// surprise, and whichever answers gets logged -- that is the part of this
// worth learning.
static GetCreatedJavaVMsFn FindGetCreatedJavaVMs(const char** found_in) {
  void* symbol = dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
  if (symbol != NULL) {
    *found_in = "RTLD_DEFAULT";
    return (GetCreatedJavaVMsFn)symbol;
  }

  static const char* kLibraries[] = {"libnativehelper.so", "libart.so", "libandroid_runtime.so"};
  for (size_t i = 0; i < sizeof(kLibraries) / sizeof(kLibraries[0]); i++) {
    void* library = dlopen(kLibraries[i], RTLD_NOW);
    if (library == NULL) {
      LOG("  dlopen(%s) failed: %s", kLibraries[i], dlerror());
      continue;
    }
    symbol = dlsym(library, "JNI_GetCreatedJavaVMs");
    if (symbol != NULL) {
      *found_in = kLibraries[i];
      return (GetCreatedJavaVMsFn)symbol;
    }
  }
  return NULL;
}

// JNI leaves an exception raised across calls, so every one has to be followed
// by this or the next call misbehaves.
static int Threw(JNIEnv* env, const char* what) {
  if (!(*env)->ExceptionCheck(env)) return 0;
  LOG("  %s: threw", what);
  // Lands in logcat under System.err. Worth the noise: without it the only
  // signal is that something failed, and which is the interesting part.
  (*env)->ExceptionDescribe(env);
  (*env)->ExceptionClear(env);
  return 1;
}

static void ReportThreadName(JNIEnv* env) {
  jclass thread = (*env)->FindClass(env, "java/lang/Thread");
  if (Threw(env, "FindClass(Thread)") || thread == NULL) return;

  jmethodID current =
      (*env)->GetStaticMethodID(env, thread, "currentThread", "()Ljava/lang/Thread;");
  jmethodID get_name = (*env)->GetMethodID(env, thread, "getName", "()Ljava/lang/String;");
  if (Threw(env, "Thread methods") || current == NULL || get_name == NULL) return;

  jobject self = (*env)->CallStaticObjectMethod(env, thread, current);
  if (Threw(env, "currentThread") || self == NULL) return;
  jstring name = (jstring)(*env)->CallObjectMethod(env, self, get_name);
  if (Threw(env, "getName") || name == NULL) return;

  const char* utf = (*env)->GetStringUTFChars(env, name, NULL);
  LOG("  Thread.currentThread().getName() = %s", utf == NULL ? "?" : utf);
  if (utf != NULL) (*env)->ReleaseStringUTFChars(env, name, utf);
}

static void ReportStaticInt(JNIEnv* env, const char* class_name, const char* field) {
  jclass found = (*env)->FindClass(env, class_name);
  if (Threw(env, class_name) || found == NULL) return;
  jfieldID id = (*env)->GetStaticFieldID(env, found, field, "I");
  if (Threw(env, field) || id == NULL) return;
  LOG("  %s.%s = %d", class_name, field, (*env)->GetStaticIntField(env, found, id));
}

// Whether a no-argument static getter returns null. Both of the ones asked
// about below are set up by ActivityThread.main, so null is evidence of having
// arrived before it -- which is the entire point of the timing.
static void ReportStaticObjectIsNull(JNIEnv* env, const char* class_name, const char* method,
                                     const char* signature) {
  jclass found = (*env)->FindClass(env, class_name);
  if (Threw(env, class_name) || found == NULL) return;
  jmethodID id = (*env)->GetStaticMethodID(env, found, method, signature);
  if (Threw(env, method) || id == NULL) return;
  jobject value = (*env)->CallStaticObjectMethod(env, found, id);
  if (Threw(env, method)) return;
  LOG("  %s.%s() = %s", class_name, method, value == NULL ? "null" : "non-null");
}

// java.lang.BootClassLoader -- the parent of the system loader, and the only
// thing in the chain this early that is certain to exist.
//
// Parenting our dex to it rather than to the app's loader is deliberate: an
// app's classpath can hold a shrunk, renamed copy of the very library we are
// about to load, and delegation would find theirs first.
static jobject BootClassLoader(JNIEnv* env) {
  jclass loader = (*env)->FindClass(env, "java/lang/ClassLoader");
  if (Threw(env, "FindClass(ClassLoader)") || loader == NULL) return NULL;

  jmethodID get_system =
      (*env)->GetStaticMethodID(env, loader, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
  jmethodID get_parent = (*env)->GetMethodID(env, loader, "getParent", "()Ljava/lang/ClassLoader;");
  if (Threw(env, "ClassLoader methods") || get_system == NULL || get_parent == NULL) return NULL;

  jobject system = (*env)->CallStaticObjectMethod(env, loader, get_system);
  if (Threw(env, "getSystemClassLoader") || system == NULL) return NULL;

  jobject parent = (*env)->CallObjectMethod(env, system, get_parent);
  if (Threw(env, "getParent")) return NULL;
  return parent;
}

// The loader over our dex, held as a global reference because stage three
// builds the app's loader in front of it, long after the frame it was made in
// has gone. It is also what defines every class we ship, keystork.Loader
// included -- a loader cannot load itself.
static jobject g_bootstrap = NULL;

// The class loaded through the tracee's own loadClass, rather than FindClass:
// FindClass resolves against the caller's loader, which has never heard of any
// of this.
static jclass LoadClass(JNIEnv* env, jobject loader, const char* name) {
  jclass loader_class = (*env)->FindClass(env, "java/lang/ClassLoader");
  jmethodID load_class =
      (*env)->GetMethodID(env, loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
  if (Threw(env, "loadClass id") || load_class == NULL) return NULL;

  jstring wanted = (*env)->NewStringUTF(env, name);
  jclass found = (jclass)(*env)->CallObjectMethod(env, loader, load_class, wanted);
  if (Threw(env, name) || found == NULL) return NULL;
  return found;
}

// Loads the embedded dex and calls keystork.Agent.probe(), logging what it
// says. Returns 0 on success.
static int RunEmbeddedDex(JNIEnv* env) {
  const jlong size = (jlong)(kKeystorkDexEnd - kKeystorkDexStart);
  LOG("  dex is %lld bytes", (long long)size);

  // Cast away const: ART only ever reads a dex opened this way.
  jobject buffer = (*env)->NewDirectByteBuffer(env, (void*)kKeystorkDexStart, size);
  if (Threw(env, "NewDirectByteBuffer") || buffer == NULL) return -10;

  jclass in_memory = (*env)->FindClass(env, "dalvik/system/InMemoryDexClassLoader");
  if (Threw(env, "FindClass(InMemoryDexClassLoader)") || in_memory == NULL) return -11;
  jmethodID ctor = (*env)->GetMethodID(env, in_memory, "<init>",
                                       "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
  if (Threw(env, "InMemoryDexClassLoader ctor") || ctor == NULL) return -12;

  jobject loader = (*env)->NewObject(env, in_memory, ctor, buffer, BootClassLoader(env));
  if (Threw(env, "new InMemoryDexClassLoader") || loader == NULL) return -13;
  g_bootstrap = (*env)->NewGlobalRef(env, loader);

  jclass agent = LoadClass(env, loader, "keystork.Agent");
  if (agent == NULL) return -15;

  jmethodID probe = (*env)->GetStaticMethodID(env, agent, "probe", "()Ljava/lang/String;");
  if (Threw(env, "probe id") || probe == NULL) return -16;
  jstring said = (jstring)(*env)->CallStaticObjectMethod(env, agent, probe);
  if (Threw(env, "probe()") || said == NULL) return -17;

  const char* utf = (*env)->GetStringUTFChars(env, said, NULL);
  LOG("  keystork.Agent.probe() = %s", utf == NULL ? "?" : utf);
  if (utf != NULL) (*env)->ReleaseStringUTFChars(env, said, utf);
  return 0;
}

// This thread's JNIEnv, or NULL with the reason logged.
//
// GetEnv rather than AttachCurrentThread: every caller runs on the app's own
// main thread, already attached and sitting inside a JNI native method --
// exactly the thread state JNI calls are legal from.
static JNIEnv* CurrentEnv(int verbose) {
  const char* found_in = "";
  GetCreatedJavaVMsFn get_vms = FindGetCreatedJavaVMs(&found_in);
  if (get_vms == NULL) {
    LOG("  no JNI_GetCreatedJavaVMs anywhere reachable");
    return NULL;
  }
  if (verbose) LOG("  JNI_GetCreatedJavaVMs from %s", found_in);

  JavaVM* vm = NULL;
  jsize count = 0;
  if (get_vms(&vm, 1, &count) != JNI_OK || count == 0 || vm == NULL) {
    LOG("  no VM (count=%d)", (int)count);
    return NULL;
  }

  JNIEnv* env = NULL;
  if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK || env == NULL) {
    LOG("  GetEnv failed; this thread is not attached to the VM");
    return NULL;
  }
  return env;
}

// Called by the injector, on the target's own main thread, with the process
// stopped. Returns 0 when the VM was reachable and Java ran.
EXPORT int keystork_arm(void) {
  char cmdline[256];
  ReadProcLine("/proc/self/cmdline", cmdline, sizeof(cmdline));
  LOG("armed: pid=%d tid=%d threads=%d cmdline=%s", getpid(), gettid(), CountThreads(), cmdline);

  JNIEnv* env = CurrentEnv(1);
  if (env == NULL) return -1;

  ReportThreadName(env);
  ReportStaticInt(env, "android/os/Build$VERSION", "SDK_INT");
  ReportStaticObjectIsNull(env, "android/app/ActivityThread", "currentActivityThread",
                           "()Landroid/app/ActivityThread;");
  ReportStaticObjectIsNull(env, "android/os/Looper", "getMainLooper", "()Landroid/os/Looper;");

  const int dex = RunEmbeddedDex(env);
  if (dex != 0) {
    LOG("  our own dex would not run (%d)", dex);
    return dex;
  }

  LOG("  our java is running in the target");
  return 0;
}

// ---------------------------------------------------------------------------
// Stage three: the bind
//
// ActivityThread.handleBindApplication is where a process stops being generic
// and becomes a particular app: it builds the LoadedApk, which builds the
// PathClassLoader over the app's dex, and instantiates the app's Application
// class, its AppComponentFactory and its content providers -- by name, off
// that LoadedApk. All of it is driven by the AppBindData the system server
// sent, and none of it has happened while the message is still on the queue.
//
// So this runs there, and does two things:
//
//   answers the names. The Application class becomes ours; the component the
//   process was started for is answered by Loader's substitution map; the
//   AppComponentFactory and the providers are cleared, because the framework's
//   own DEFAULT factory does everything we need and no provider of the app's
//   is wanted. None of this blocks anything -- the framework asks for a name
//   and gets a class, it is simply never one of the app's.
//
//   builds the LoadedApk early, with mClassLoader already set to ours.
//   getPackageInfo caches by package name and getClassLoader short-circuits on
//   a non-null mClassLoader before taking its lock, so handleBindApplication
//   finds ours and never constructs a PathClassLoader. The app's dex is then
//   absent from every classpath in the process rather than merely unused, and
//   a name we did not answer is a loud ClassNotFoundException rather than app
//   code running quietly.
//
// Pre-setting mClassLoader also settles the AppComponentFactory on its own:
// LoadedApk's constructor calls createAppFactory with mBaseClassLoader, which
// handleBindApplication passes as null, so the factory is the framework's
// DEFAULT. The app's own factory is only ever instantiated inside
// createOrUpdateClassLoaderLocked, which now never runs.
// ---------------------------------------------------------------------------

// Whatever we hand to Java and need to survive a GC we do not control. The
// LoadedApk especially: ActivityThread caches it through a WeakReference, so
// without a strong one here it could be collected between now and the bind.
static jobject g_loaded_apk = NULL;
static jobject g_loader = NULL;

// Our end of the socketpair the daemon opened while the process was stopped.
//
// It is an ordinary descriptor in this process by the time anything here runs;
// the daemon made it by having us call socketpair() and then took the other
// end with pidfd_getfd, so it was never named, bound or connected to. Java
// reaches it through keystork.Agent.socketFd(), registered below, and adopts
// it with ParcelFileDescriptor.adoptFd.
static int g_channel = -1;

static jint ChannelFd(JNIEnv* env, jclass ignored) {
  (void)env;
  (void)ignored;
  return g_channel;
}

// Java cannot dlopen us -- we are a memfd mapping with no name to load -- so
// the binding goes the other way: we hand the class its native method while we
// still have a JNIEnv of our own.
static int RegisterChannelAccess(JNIEnv* env) {
  jclass agent = LoadClass(env, g_bootstrap, "keystork.Agent");
  if (agent == NULL) return -1;

  const JNINativeMethod method = {"socketFd", "()I", (void*)ChannelFd};
  if ((*env)->RegisterNatives(env, agent, &method, 1) != JNI_OK) {
    Threw(env, "RegisterNatives(socketFd)");
    return -1;
  }
  return 0;
}

// The Application the framework will instantiate in place of the app's.
static const char kApplicationClass[] = "keystork.Shell";

// What Loader answers the launched component with.
static const char kActivityClass[] = "keystork.Blank";

// Builds the loader the app gets: keystork.Loader in front of the dex loader,
// carrying the map from the names the framework will ask for to the ones we
// ship.
//
// `launch_component` is the class the system server started this process to
// run. It comes from the target's manifest, so it cannot be known at build
// time and the daemon passes it in; NULL or empty means nothing to answer,
// which is the case when the process was started some other way.
static jobject BuildLoader(JNIEnv* env, const char* launch_component) {
  jclass loader_class = LoadClass(env, g_bootstrap, "keystork.Loader");
  if (loader_class == NULL) return NULL;

  jmethodID ctor = (*env)->GetMethodID(env, loader_class, "<init>",
                                       "(Ljava/lang/ClassLoader;[Ljava/lang/String;)V");
  if (Threw(env, "Loader ctor") || ctor == NULL) return NULL;

  const jsize count = (launch_component != NULL && launch_component[0] != '\0') ? 2 : 0;
  jclass string = (*env)->FindClass(env, "java/lang/String");
  jobjectArray pairs = (*env)->NewObjectArray(env, count, string, NULL);
  if (Threw(env, "String[]") || pairs == NULL) return NULL;
  if (count == 2) {
    (*env)->SetObjectArrayElement(env, pairs, 0, (*env)->NewStringUTF(env, launch_component));
    (*env)->SetObjectArrayElement(env, pairs, 1, (*env)->NewStringUTF(env, kActivityClass));
  } else {
    LOG("  no launch component was named; nothing to answer for it");
  }

  jobject built = (*env)->NewObject(env, loader_class, ctor, g_bootstrap, pairs);
  if (Threw(env, "new keystork.Loader") || built == NULL) return NULL;
  return built;
}

// A field's value, or NULL with the exception cleared. `Threw` reports which
// one so a field the platform has renamed says so by name.
static jobject GetObjectFieldNamed(JNIEnv* env, jobject object, jclass type, const char* name,
                                   const char* signature) {
  jfieldID id = (*env)->GetFieldID(env, type, name, signature);
  if (Threw(env, name) || id == NULL) return NULL;
  return (*env)->GetObjectField(env, object, id);
}

static int SetObjectFieldNamed(JNIEnv* env, jobject object, jclass type, const char* name,
                               const char* signature, jobject value) {
  jfieldID id = (*env)->GetFieldID(env, type, name, signature);
  if (Threw(env, name) || id == NULL) return -1;
  (*env)->SetObjectField(env, object, id, value);
  return Threw(env, name) ? -1 : 0;
}

// Replaces a String field, logging what it held. `value` may be NULL to clear
// it. The old names are the whole point of the log line: each one is app code
// the framework would otherwise have loaded by it.
static void SetStringField(JNIEnv* env, jobject object, jclass type, const char* name,
                           const char* value) {
  jfieldID id = (*env)->GetFieldID(env, type, name, "Ljava/lang/String;");
  if (Threw(env, name) || id == NULL) return;

  jstring was = (jstring)(*env)->GetObjectField(env, object, id);
  const char* utf = was == NULL ? NULL : (*env)->GetStringUTFChars(env, was, NULL);
  LOG("  %s = %s -> %s", name, was == NULL ? "(null)" : (utf == NULL ? "?" : utf),
      value == NULL ? "(null)" : value);
  if (utf != NULL) (*env)->ReleaseStringUTFChars(env, was, utf);

  (*env)->SetObjectField(env, object, id, value == NULL ? NULL : (*env)->NewStringUTF(env, value));
}

// The bind data, if the main thread has got that far. Two ways of asking,
// because they cover different halves of the window:
//
//   ActivityThread.mBoundApplication is set at the top of
//   handleBindApplication, so it answers once the dispatch has begun.
//
//   the message itself, still on the main looper's queue, answers before the
//   dispatch -- which is where we normally are, since MessageQueue.next()
//   polls before it dequeues.
//
// Either way the process is stopped, so what is found cannot move underneath
// us.
static jobject FindBindData(JNIEnv* env) {
  jclass activity_thread = (*env)->FindClass(env, "android/app/ActivityThread");
  if (Threw(env, "FindClass(ActivityThread)") || activity_thread == NULL) return NULL;

  jmethodID current = (*env)->GetStaticMethodID(env, activity_thread, "currentActivityThread",
                                                "()Landroid/app/ActivityThread;");
  if (Threw(env, "currentActivityThread id") || current == NULL) return NULL;
  jobject thread = (*env)->CallStaticObjectMethod(env, activity_thread, current);
  if (Threw(env, "currentActivityThread") || thread == NULL) return NULL;

  jobject bound = GetObjectFieldNamed(env, thread, activity_thread, "mBoundApplication",
                                      "Landroid/app/ActivityThread$AppBindData;");
  if (bound != NULL) {
    LOG("  handleBindApplication has already begun");
    return bound;
  }

  jclass looper = (*env)->FindClass(env, "android/os/Looper");
  if (Threw(env, "FindClass(Looper)") || looper == NULL) return NULL;
  jmethodID get_main =
      (*env)->GetStaticMethodID(env, looper, "getMainLooper", "()Landroid/os/Looper;");
  if (Threw(env, "getMainLooper id") || get_main == NULL) return NULL;
  jobject main = (*env)->CallStaticObjectMethod(env, looper, get_main);
  if (Threw(env, "getMainLooper") || main == NULL) return NULL;

  jmethodID get_queue =
      (*env)->GetMethodID(env, looper, "getQueue", "()Landroid/os/MessageQueue;");
  if (Threw(env, "getQueue id") || get_queue == NULL) return NULL;
  jobject queue = (*env)->CallObjectMethod(env, main, get_queue);
  if (Threw(env, "getQueue") || queue == NULL) return NULL;

  jclass queue_class = (*env)->GetObjectClass(env, queue);
  jclass message = (*env)->FindClass(env, "android/os/Message");
  jclass bind_data = (*env)->FindClass(env, "android/app/ActivityThread$AppBindData");
  if (Threw(env, "message classes") || message == NULL || bind_data == NULL) return NULL;

  jfieldID next = (*env)->GetFieldID(env, message, "next", "Landroid/os/Message;");
  jfieldID payload = (*env)->GetFieldID(env, message, "obj", "Ljava/lang/Object;");
  if (Threw(env, "Message fields") || next == NULL || payload == NULL) return NULL;

  jobject found = NULL;
  for (jobject queued = GetObjectFieldNamed(env, queue, queue_class, "mMessages",
                                            "Landroid/os/Message;");
       queued != NULL && found == NULL;
       queued = (*env)->GetObjectField(env, queued, next)) {
    jobject carried = (*env)->GetObjectField(env, queued, payload);
    if (carried != NULL && (*env)->IsInstanceOf(env, carried, bind_data)) {
      LOG("  the bind message is on the main looper, not yet dispatched");
      found = carried;
    }
  }
  return found;
}

// Called by the injector at each of a series of stopping points on the way to
// handleBindApplication, with the class the process was started to run --
// which the daemon knows, because it is what it asked `am` to start. Returns 1
// once the surgery is done, 0 while the bind data is still out of reach, and
// negative if something that should have worked did not.
EXPORT int keystork_bind(const char* launch_component, int channel) {
  JNIEnv* env = CurrentEnv(0);
  if (env == NULL) return -1;
  if (g_bootstrap == NULL) {
    LOG("  no dex loaded; stage two did not get that far");
    return -2;
  }
  g_channel = channel;

  jobject data = FindBindData(env);
  if (data == NULL) {
    // Not an error: the usual answer until the system server has sent the
    // bind. Any exception raised looking is ours to clear.
    (*env)->ExceptionClear(env);
    return 0;
  }

  jclass data_class = (*env)->GetObjectClass(env, data);
  jobject app_info =
      GetObjectFieldNamed(env, data, data_class, "appInfo", "Landroid/content/pm/ApplicationInfo;");
  jobject compat_info = GetObjectFieldNamed(env, data, data_class, "compatInfo",
                                            "Landroid/content/res/CompatibilityInfo;");
  if (app_info == NULL) {
    LOG("  the bind data has no appInfo");
    return -3;
  }

  // The loader first: everything below is only worth writing if the classes
  // the framework is about to ask for can actually be found.
  jobject loader = BuildLoader(env, launch_component);
  if (loader == NULL) return -11;
  g_loader = (*env)->NewGlobalRef(env, loader);

  // keystork.Loader carries no dex of its own and delegates to the one that
  // does, so every class the app ends up running -- Shell included -- is
  // defined by g_bootstrap. Registering on the Agent from there is therefore
  // registering on the very class Shell will reach.
  if (RegisterChannelAccess(env) != 0) return -12;

  // Then the names. getCustomApplicationClassNameForProcess consults
  // mAppClassNamesByProcess before className, so clearing it is what makes
  // className the only answer -- an app declaring a per-process Application
  // class would otherwise sail straight past ours.
  jclass app_info_class = (*env)->GetObjectClass(env, app_info);
  SetStringField(env, app_info, app_info_class, "className", kApplicationClass);
  SetStringField(env, app_info, app_info_class, "appComponentFactory", NULL);
  SetObjectFieldNamed(env, app_info, app_info_class, "mAppClassNamesByProcess",
                      "Landroid/util/ArrayMap;", NULL);

  // Providers are instantiated by name too, out of installContentProviders,
  // and a null list is the same "nothing declared" the framework handles for
  // every app that has none.
  SetObjectFieldNamed(env, data, data_class, "providers", "Ljava/util/List;", NULL);

  // Now the classpath. getPackageInfoNoCheck builds the LoadedApk and caches
  // it under the package name, which is where handleBindApplication will look.
  jclass activity_thread = (*env)->FindClass(env, "android/app/ActivityThread");
  jmethodID current = (*env)->GetStaticMethodID(env, activity_thread, "currentActivityThread",
                                                "()Landroid/app/ActivityThread;");
  jobject thread = (*env)->CallStaticObjectMethod(env, activity_thread, current);
  if (Threw(env, "currentActivityThread") || thread == NULL) return -4;

  jmethodID no_check = (*env)->GetMethodID(
      env, activity_thread, "getPackageInfoNoCheck",
      "(Landroid/content/pm/ApplicationInfo;Landroid/content/res/CompatibilityInfo;)"
      "Landroid/app/LoadedApk;");
  if (Threw(env, "getPackageInfoNoCheck id") || no_check == NULL) return -5;

  jobject apk = (*env)->CallObjectMethod(env, thread, no_check, app_info, compat_info);
  if (Threw(env, "getPackageInfoNoCheck") || apk == NULL) return -6;

  jclass apk_class = (*env)->GetObjectClass(env, apk);
  if (SetObjectFieldNamed(env, apk, apk_class, "mClassLoader", "Ljava/lang/ClassLoader;",
                          g_loader) != 0) {
    return -7;
  }
  g_loaded_apk = (*env)->NewGlobalRef(env, apk);

  // Ask the way the framework will: getClassLoader() returning ours is the
  // whole claim, and it is cheap to check while we can still say so.
  jmethodID get_loader =
      (*env)->GetMethodID(env, apk_class, "getClassLoader", "()Ljava/lang/ClassLoader;");
  if (Threw(env, "getClassLoader id") || get_loader == NULL) return -8;
  jobject answered = (*env)->CallObjectMethod(env, apk, get_loader);
  if (Threw(env, "getClassLoader")) return -9;
  if (!(*env)->IsSameObject(env, answered, g_loader)) {
    LOG("  LoadedApk.getClassLoader() is not ours; the app's dex is still on the classpath");
    return -10;
  }

  LOG("  the app's LoadedApk now answers with our class loader");
  return 1;
}
