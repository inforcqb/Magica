#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/capability.h>
#include <lsplt.hpp>
#include <api/system_properties.h>
#include <sys/xattr.h>
#include "logging.h"
#include "android_filesystem_config.h"

#define arraysize(array) (sizeof(array)/sizeof(array[0]))

static int skip_capset(cap_user_header_t header __unused, cap_user_data_t data __unused) {
    LOGD("Skip capset");
    return 0;
}

static jboolean root(JNIEnv *env  __unused, jclass clazz __unused) {
    if (setresuid(AID_ROOT, AID_ROOT, AID_ROOT)) {
        PLOGE("setresuid");
        return false;
    } else if (geteuid() == AID_ROOT) {
        LOGI("We Are Root!!!");
        if (setresgid(AID_ROOT, AID_ROOT, AID_ROOT)) {
            PLOGE("setresgid");
        }
        gid_t groups[] = {AID_SYSTEM, AID_ADB, AID_LOG, AID_INPUT, AID_INET,
                          AID_NET_BT, AID_NET_BT_ADMIN, AID_SDCARD_R, AID_SDCARD_RW,
                          AID_NET_BW_STATS, AID_READPROC, AID_UHID, AID_EXT_DATA_RW,
                          AID_EXT_OBB_RW, AID_READTRACEFS};
        if (setgroups(arraysize(groups), groups)) {
            PLOGE("setgroups");
        }
        return true;
    } else {
        return false;
    }
}

static void resetprop(const char *name, const char *value) {
    auto pi = const_cast<prop_info *>(__system_property_find(name));
    if (pi != nullptr && strncmp(name, "ro.", strlen("ro.")) == 0) {
        __system_property_delete(name, false);
        pi = nullptr;
    }
    int ret;
    if (pi != nullptr) {
        ret = __system_property_update(pi, value, strlen(value));
        LOGD("resetprop: update prop [%s]: [%s]", name, value);
    } else {
        ret = __system_property_add(name, strlen(name), value, strlen(value));
        LOGD("resetprop: create prop [%s]: [%s]", name, value);
    }
    if (ret) {
        LOGW("resetprop: set prop error");
    }
}

/* Make adbd run as root, then fall back to repairing it.
 *
 * The requested recipe first: /proc/sys/fs/suid_dumpable <- 0 (adbd is said to read
 * that as "this is a debug build"), together with ro.debuggable=1 / ro.secure=0 and a
 * restart of adbd.  If the new adbd really is root, we are done and the two props are
 * put back.
 *
 * If it is not, the fallback matters, because this handset is a user/release build
 * where adbd is compiled with ALLOW_ADBD_ROOT=0 and the root request is answered with
 * "adbd cannot run as root in production builds" *even when ro.debuggable is already
 * 1*.  In that case we clear service.adb.root, restore the props and restart adbd
 * until it is running as shell again -- otherwise adb is left dead (USB debugging
 * shows enabled in Settings while nothing listens on the socket).
 *
 * Everything is logged, and the waits are bounded (upstream's loop had no exit
 * condition at all, which is what froze the UI).
 */
static jboolean adb_root(JNIEnv *env  __unused, jclass clazz __unused) {
    char old_pid[32] = {};
    char pid[32] = {};
    char path[32] = {};
    struct stat st{};

    __system_properties_init();
    __system_property_get("init.svc_debug_pid.adbd", old_pid);
    LOGI("adb root: start (adbd pid was '%s')", old_pid);

    {
        const int fd = open("/proc/sys/fs/suid_dumpable", O_WRONLY);
        if (fd < 0) {
            LOGW("adb root: cannot open /proc/sys/fs/suid_dumpable: %s",
                 strerror(errno));
        } else {
            const ssize_t w = write(fd, "0\n", 2);
            LOGI("adb root: suid_dumpable <- 0 (%zd, errno=%d)", w, errno);
            close(fd);
        }
    }
    resetprop("ro.debuggable", "1");
    resetprop("ro.secure", "0");
    system("/system/bin/setprop ctl.restart adbd");

    // Bounded wait for an adbd that is actually root.
    struct timespec t0{}, now{};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    long waited_ms = 0;
    while (true) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        waited_ms = (now.tv_sec - t0.tv_sec) * 1000L +
                    (now.tv_nsec - t0.tv_nsec) / 1000000L;
        if (waited_ms > 15000) break;
        __system_property_get("init.svc_debug_pid.adbd", pid);
        if (pid[0] == '\0' || strcmp(pid, old_pid) == 0) { usleep(10000); continue; }
        snprintf(path, sizeof(path), "/proc/%s", pid);
        if (stat(path, &st) != 0) { usleep(10000); continue; }
        if (st.st_uid == 0) {
            LOGI("adb root: adbd is running as ROOT (pid=%s)", pid);
            resetprop("ro.debuggable", "0");
            resetprop("ro.secure", "1");
            return true;
        }
        if (st.st_uid == AID_SHELL) {
            LOGW("adb root: adbd came back as shell (pid=%s) -- falling back to repair", pid);
            break;
        }
        usleep(10000);
    }
    LOGW("adb root: no root adbd after %ld ms; repairing adb instead", waited_ms);

    resetprop("ro.debuggable", "0");
    resetprop("ro.secure", "1");
    system("/system/bin/setprop service.adb.root 0");
    system("/system/bin/setprop ctl.restart adbd");

    clock_gettime(CLOCK_MONOTONIC, &t0);
    while (true) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        long waited = (now.tv_sec - t0.tv_sec) * 1000L +
                      (now.tv_nsec - t0.tv_nsec) / 1000000L;
        if (waited > 15000) {
            LOGW("repair adbd: gave up after %ld ms (adbd pid still '%s')",
                 waited, pid);
            return false;
        }
        __system_property_get("init.svc_debug_pid.adbd", pid);
        if (pid[0] == '\0') {           // not even started yet
            usleep(10000);
            continue;
        }
        snprintf(path, sizeof(path), "/proc/%s", pid);
        if (stat(path, &st) != 0) {     // it died again; wait for the next one
            usleep(10000);
            continue;
        }
        if (st.st_uid == AID_SHELL) {
            LOGI("repair adbd: running as shell again (pid=%s)", pid);
            return true;
        }
        usleep(10000);
    }
}

static void signal_handler(int sig) {
    if (sig != SIGSYS) return;
    LOGW("received signal: SIGSYS, setresuid fail");
}

jint JNI_OnLoad(JavaVM *jvm, void *v __unused) {
    JNIEnv *env;
    jclass clazz;

    if (jvm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    if ((clazz = env->FindClass("io/github/vvb2060/puellamagi/MagicaService")) == nullptr) {
        return JNI_ERR;
    }

    JNINativeMethod methods[] = {
            {"root",     "()Z", (void *) root},
            {"adb_root", "()Z", (void *) adb_root},
    };
    if (env->RegisterNatives(clazz, methods, arraysize(methods)) < 0) {
        return JNI_ERR;
    }

    signal(SIGSYS, signal_handler);

#if defined(__LP64__)
    const char *runtime_path = "/system/lib64/libandroid_runtime.so";
#else
    const char *runtime_path = "/system/lib/libandroid_runtime.so";
#endif

    struct stat st{};
    if (stat(runtime_path, &st) != 0) {
        PLOGE("stat %s", runtime_path);
    } else {
        LOGV("stat: dev=%lu, inode=%lu, path=%s",
             (unsigned long) st.st_dev, (unsigned long) st.st_ino, runtime_path);
        if (lsplt::RegisterHook(st.st_dev, st.st_ino, "capset", (void *) skip_capset, nullptr)) {
            if (!lsplt::CommitHook()) {
                PLOGE("CommitHook failed");
            } else {
                LOGD("CommitHook success");
            }
        } else {
            PLOGE("Failed to register hook");
        }
    }

    return JNI_VERSION_1_6;
}
