package io.github.vvb2060.puellamagi;

import static io.github.vvb2060.puellamagi.App.TAG;

import android.app.ActivityManager;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import java.io.IOException;
import java.util.List;

public final class MagicaService extends Service {
    private Process process;
    private final IRemoteService.Stub binder = new IRemoteService.Stub() {

        @Override
        public IRemoteProcess getRemoteProcess() {
            return new RemoteProcessHolder(process);
        }

        @Override
        public List<ActivityManager.RunningAppProcessInfo> getRunningAppProcesses() {
            return getSystemService(ActivityManager.class).getRunningAppProcesses();
        }

        @Override
        public boolean adbRoot() {
            return root() && adb_root();
        }
    };

    static native boolean root();

    static native boolean adb_root();

    /* Expose this uid-0 shell over loopback so `adb shell` -- which has no root --
     * can open a root shell without any kernel write.  Daemonises itself. */
    static native boolean start_shell_server();

    public IBinder onBind(Intent intent) {
        try {
            root();
            process = Runtime.getRuntime().exec("sh");
            if (start_shell_server()) {
                Log.i(TAG, "root shell server: 127.0.0.1:1337 (token /data/local/tmp/gl-w1/rshell.token)");
            } else {
                Log.w(TAG, "root shell server: not started");
            }
            return binder;
        } catch (IOException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return null;
        }
    }
}
