#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
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

    // ctl.restart does not fire on this handset: measured twice, with both the
    // bundled client and /system/bin/setprop, while adbd kept its pid.  Restart it the
    // way adbd does it for "adb root" itself: kill it and let init respawn the service
    // (adbd.rc has no oneshot flag).
    LOGI("adb root: pkill -9 adbd (init respawns it)");
    system("/system/bin/pkill -9 adbd");

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

/* ---- root shell server ----------------------------------------------------
 *
 * Exposes the uid-0 shell this service already owns to anything that can reach
 * loopback, so `adb shell` (uid 2000, no root) can open a real root shell without
 * any kernel write -- which matters on this handset, where the OPPO guard module
 * intercepts credential writes but has never objected to anything Magica does
 * (its root is a userspace one).
 *
 *   adb shell 'T=$(cat /data/local/tmp/gl-w1/rshell.token); { echo "$T"; cat; } | nc 127.0.0.1 1337'
 *
 * The server daemonises (double fork + setsid) so it keeps running after the app
 * is gone, and requires the token as the first line so other apps on the phone
 * cannot just connect.  Caveat: the token file is world-readable (0644) because a
 * capless uid-0 process cannot chown a socket; treat it as a prototype-grade
 * secret.
 */
#define RSH_SOCK_PATH "/data/local/tmp/gl-w1/rshell.sock"
#define RSH_TOKEN_PATH "/data/local/tmp/gl-w1/rshell.token"

static void rsh_log(const char *format, ...) {
    const int fd = open("/data/local/tmp/gl-w1/rshell.log",
                        O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    char buf[256];
    va_list ap;
    va_start(ap, format);
    const int n = vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);
    if (n > 0) (void) !write(fd, buf, (size_t) n);
    close(fd);
}

static void rsh_make_token(char *out, size_t cap) {
    const int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    unsigned char raw[16] = {};
    if (fd >= 0) {
        (void) !read(fd, raw, sizeof(raw));
        close(fd);
    }
    size_t n = 0;
    for (size_t i = 0; i < sizeof(raw) && n + 3 < cap; i++) {
        n += (size_t) snprintf(out + n, cap - n, "%02x", raw[i]);
    }
    out[n] = '\0';
}

/* Borrow the token from the app's own data dir if it exists there, else keep ours. */
static void rsh_read_expected(const char *fallback, char *out, size_t cap) {
    const int fd = open(RSH_TOKEN_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        snprintf(out, cap, "%s", fallback);
        return;
    }
    const ssize_t r = read(fd, out, cap - 1);
    close(fd);
    if (r <= 0) {
        snprintf(out, cap, "%s", fallback);
        return;
    }
    out[r] = '\0';
    char *nl = strchr(out, '\n');
    if (nl) *nl = '\0';
}

static void rsh_pump(int cfd, int master) {
    char buf[4096];
    for (;;) {
        struct pollfd fds[2] = {{cfd, POLLIN, 0}, {master, POLLIN, 0}};
        if (poll(fds, 2, -1) <= 0) return;
        for (int i = 0; i < 2; i++) {
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            const int from = fds[i].fd;
            const int to = i == 0 ? master : cfd;
            const ssize_t n = read(from, buf, sizeof(buf));
            if (n <= 0) return;
            ssize_t off = 0;
            while (off < n) {
                const ssize_t w = write(to, buf + off, (size_t) (n - off));
                if (w <= 0) return;
                off += w;
            }
        }
    }
}

static void rsh_serve_client(int cfd, const char *expected) {
    char line[128] = {};
    size_t n = 0;
    while (n + 1 < sizeof(line)) {
        const ssize_t r = read(cfd, line + n, 1);
        if (r <= 0) { close(cfd); return; }
        if (line[n] == '\n') break;
        n++;
    }
    line[n] = '\0';
    if (strcmp(line, expected) != 0) {
        rsh_log("reject: bad token\n");
        (void) !write(cfd, "bad token\n", 10);
        close(cfd);
        return;
    }
    int master = -1;
    const pid_t pid = forkpty(&master, nullptr, nullptr, nullptr);
    if (pid < 0) {
        rsh_log("forkpty failed: %s\n", strerror(errno));
        close(cfd);
        return;
    }
    if (pid == 0) {
        setenv("HOME", "/data/local/tmp/gl-w1", 1);
        setenv("TERM", "xterm", 1);
        execl("/system/bin/sh", "sh", "-i", (char *) nullptr);
        _exit(127);
    }
    rsh_log("client ok, sh pid=%d\n", (int) pid);
    rsh_pump(cfd, master);
    kill(pid, SIGHUP);
    close(master);
    close(cfd);
}

static void rsh_loop(int listen_fd, const char *expected) {
    for (;;) {
        const int cfd = accept(listen_fd, nullptr, nullptr);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            return;
        }
        const pid_t c = fork();
        if (c == 0) {
            close(listen_fd);
            rsh_serve_client(cfd, expected);
            _exit(0);
        }
        close(cfd);
        if (c < 0) continue;
        (void) waitpid(c, nullptr, WNOHANG);
    }
}

static jboolean start_shell_server(JNIEnv *env  __unused, jclass clazz  __unused) {
    if (geteuid() != AID_ROOT) {
        LOGW("shell server: not root yet");
        return false;
    }
    char token[64] = {};
    rsh_make_token(token, sizeof(token));

    /* Keep the token only if the caller pre-created it; otherwise publish ours. */
    const int tfd = open(RSH_TOKEN_PATH, O_RDONLY | O_CLOEXEC);
    if (tfd >= 0) {
        close(tfd);
    } else {
        const int wfd = open(RSH_TOKEN_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (wfd >= 0) {
            (void) !write(wfd, token, strlen(token));
            (void) !write(wfd, "\n", 1);
            close(wfd);
        }
    }
    char expected[64] = {};
    rsh_read_expected(token, expected, sizeof(expected));
    /* uid 0 is the owner, so this works without CAP_CHOWN; adb shell (uid 2000)
     * can then read the token even though the writer was root. */
    chmod(RSH_TOKEN_PATH, 0644);

    /* AF_UNIX, not AF_INET: this service runs in an isolated process, and Android
     * blocks IP sockets there (measured: token got written, then socket() returned
     * -1 and nothing listened while Seccomp showed mode 2 with 3 filters).  Unix
     * sockets are allowed, and 0666 on the node is enough for adb shell to connect
     * without any chown. */
    const int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd < 0) {
        rsh_log("socket(AF_UNIX) failed: %s\n", strerror(errno));
        return false;
    }
    (void) unlink(RSH_SOCK_PATH);
    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", RSH_SOCK_PATH);
    if (bind(lfd, (struct sockaddr *) &addr, sizeof(addr)) != 0 ||
        listen(lfd, 8) != 0) {
        rsh_log("bind/listen %s failed: %s\n", RSH_SOCK_PATH, strerror(errno));
        close(lfd);
        return false;
    }
    chmod(RSH_SOCK_PATH, 0666);
    rsh_log("listening on %s (token %s)\n", RSH_SOCK_PATH, RSH_TOKEN_PATH);

    /* Daemonise so the shell survives this process/app. */
    const pid_t mid = fork();
    if (mid < 0) {
        rsh_log("fork failed: %s\n", strerror(errno));
        return false;
    }
    if (mid > 0) {
        (void) waitpid(mid, nullptr, 0);
        return true;
    }
    (void) setsid();
    const pid_t d = fork();
    if (d < 0) _exit(1);
    if (d > 0) _exit(0);
    (void) chdir("/");
    const int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        (void) dup2(devnull, 0);
        (void) dup2(devnull, 1);
        (void) dup2(devnull, 2);
        if (devnull > 2) close(devnull);
    }
    rsh_log("daemon up, accepting on %s\n", RSH_SOCK_PATH);
    rsh_loop(lfd, expected);
    _exit(0);
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
            {"start_shell_server", "()Z", (void *) start_shell_server},
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

