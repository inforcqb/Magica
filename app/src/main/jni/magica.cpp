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

/* Upstream's adb-root flow, plus one added line.
 *
 * The added line is the requested
 *     echo 0 > /proc/sys/fs/suid_dumpable
 * (written directly here, the value and errno are logged) on the theory that adbd
 * treats that sysctl as "this is a debug build" and then keeps root.
 *
 * Kept from upstream: the su:s0 pre-check, resetprop("ro.debuggable","1"),
 * resetprop("ro.secure","0"), the bundled __system_property_set("ctl.restart"), and
 * restoring the two props once adbd is root.
 *
 * Two deliberate deviations, both because of what was measured on this handset:
 *   - /system/bin/setprop ctl.restart adbd is issued as well: the bundled client's
 *     ctl write was observed to have no effect (adbd kept its pid, the adb shell
 *     never dropped), while the platform client definitely reaches init;
 *   - the wait is bounded (15 s).  Upstream's loop had no exit condition at all, and
 *     with MainActivity calling this on the UI thread that is what froze the app.
 *
 * service.adb.root is never set here: on a build whose adbd cannot run as root it
 * makes adbd exit on start, init restart-loops it, and adb is then dead while
 * Settings still shows USB debugging as enabled.
 */
static jboolean adb_root(JNIEnv *env  __unused, jclass clazz __unused) {
    char old_pid[32] = {};
    char pid[32] = {};
    char path[32] = {};
    struct stat st{};
    char selinux_context[64] = {};

    __system_properties_init();
    __system_property_get("init.svc_debug_pid.adbd", old_pid);
    if (old_pid[0] == '\0') {
        LOGW("adb root: adbd is not running (init.svc_debug_pid.adbd empty)");
    } else {
        snprintf(path, sizeof(path), "/proc/%s", old_pid);
        getxattr(path, "security.selinux", selinux_context, sizeof(selinux_context));
        LOGI("adb root: adbd pid=%s selinux=%s", old_pid, selinux_context);
        if (strncmp(selinux_context, "u:r:su:s0", strlen("u:r:su:s0")) == 0) {
            return true;
        }
    }

    /* the added line */
    {
        const int fd = open("/proc/sys/fs/suid_dumpable", O_WRONLY);
        if (fd < 0) {
            LOGW("adb root: cannot open /proc/sys/fs/suid_dumpable: %s",
                 strerror(errno));
        } else {
            const ssize_t w = write(fd, "0\n", 2);
            LOGI("adb root: suid_dumpable <- 0 (wrote %zd, errno=%d)", w, errno);
            close(fd);
        }
    }

    resetprop("ro.debuggable", "1");
    resetprop("ro.secure", "0");
    __system_property_set("ctl.restart", "adbd");
    system("/system/bin/setprop ctl.restart adbd");

    struct timespec t0{}, now{};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    while (true) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        const long waited_ms = (now.tv_sec - t0.tv_sec) * 1000L +
                               (now.tv_nsec - t0.tv_nsec) / 1000000L;
        if (waited_ms > 15000) {
            LOGW("adb root: gave up after %ld ms (adbd pid=%s, ro.debuggable=1 left "
                 "in place)", waited_ms, pid);
            return false;
        }
        __system_property_get("init.svc_debug_pid.adbd", pid);
        if (pid[0] == '\0' || strcmp(pid, old_pid) == 0) { usleep(10000); continue; }
        snprintf(path, sizeof(path), "/proc/%s", pid);
        getxattr(path, "security.selinux", selinux_context, sizeof(selinux_context));
        if (stat(path, &st) != 0) { usleep(10000); continue; }
        LOGI("adb root: new adbd pid=%s uid=%d selinux=%s", pid, (int) st.st_uid,
             selinux_context);
        if (st.st_uid == AID_SHELL) {
            LOGW("adb root: adbd dropped privileges (uid=%d) -- no root adbd on this "
                 "build", (int) st.st_uid);
            return false;
        } else if (strncmp(selinux_context, "u:r:su:s0", strlen("u:r:su:s0")) == 0) {
            LOGI("adb root: adbd running as root (selinux=%s)", selinux_context);
            resetprop("ro.debuggable", "0");
            resetprop("ro.secure", "1");
            return true;
        } else {
            usleep(10000);
        }
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
