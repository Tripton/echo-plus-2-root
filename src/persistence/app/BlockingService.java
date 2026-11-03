package org.local.lidar.binderprobe;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

/** A local Binder endpoint kept pending for the two checked kernel writes. */
public final class BlockingService extends Service {
    private final IBinder endpoint = new Binder() {
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply,
                                               int flags) throws RemoteException {
            if (code != 1) return super.onTransact(code, data, reply, flags);
            try { Thread.sleep(8000); } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            if (reply != null) reply.writeInt(0x4c494441);
            return true;
        }
    };

    @Override public IBinder onBind(Intent intent) {
        return endpoint;
    }
}
