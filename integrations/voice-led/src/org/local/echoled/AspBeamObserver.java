// SPDX-License-Identifier: Apache-2.0
package org.local.echoled;

import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import java.lang.reflect.Method;

/** Passive listener for the stock Audio Signal Processor's beam-index event. */
final class AspBeamObserver implements AutoCloseable {
    interface Sink {
        void onBeam(int index);
        void onUnavailable(String reason);
    }

    private static final String SERVICE_NAME = "audiosignalprocessor";
    private static final String SERVICE_DESCRIPTOR = "com.amazon.asp.IAudioSignalProcessor";
    private static final String LISTENER_DESCRIPTOR = "com.amazon.asp.IAudioEventListener";
    private static final int REGISTER_TRANSACTION = 1;
    private static final int UNREGISTER_TRANSACTION = 2;
    private static final int EVENT_TRANSACTION = 1;
    private static final int BEAM_EVENT = 3;

    private final IBinder service;
    private final Listener listener;
    private final IBinder.DeathRecipient deathRecipient;
    private boolean registered;

    private static final class Listener extends Binder {
        private final Sink sink;
        private volatile boolean active = true;

        Listener(Sink sink) {
            this.sink = sink;
            attachInterface(null, LISTENER_DESCRIPTOR);
        }

        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags)
                throws RemoteException {
            if (code != EVENT_TRANSACTION) return super.onTransact(code, data, reply, flags);
            data.enforceInterface(LISTENER_DESCRIPTOR);
            int eventType = data.readInt();
            int byteLength = data.readInt();
            if (active && eventType == BEAM_EVENT && byteLength == 4 && data.dataAvail() >= 4) {
                int index = data.readInt();
                // The Plus 2 has twelve LED segments. Never display an unknown index.
                if (index >= 0 && index < 12) {
                    try { sink.onBeam(index); }
                    catch (RuntimeException ignored) {
                        // A Kiosk UI/entity failure must not fail the stock ASP Binder call.
                    }
                }
            }
            if (reply != null) reply.writeNoException();
            return true;
        }

        void deactivate() { active = false; }
    }

    private AspBeamObserver(IBinder service, Sink sink) {
        this.service = service;
        this.listener = new Listener(sink);
        this.deathRecipient = () -> {
            try { sink.onUnavailable("ASP service died"); }
            catch (RuntimeException ignored) { /* Do not fail the Binder death callback. */ }
        };
    }

    static AspBeamObserver open(Sink sink) throws Exception {
        Class<?> manager = Class.forName("android.os.ServiceManager");
        Method getService = manager.getDeclaredMethod("getService", String.class);
        getService.setAccessible(true);
        IBinder service = (IBinder) getService.invoke(null, SERVICE_NAME);
        if (service == null) throw new IllegalStateException("ASP service missing");
        if (!SERVICE_DESCRIPTOR.equals(service.getInterfaceDescriptor()))
            throw new IllegalStateException("ASP descriptor mismatch");
        AspBeamObserver observer = new AspBeamObserver(service, sink);
        service.linkToDeath(observer.deathRecipient, 0);
        try {
            if (!listenerTransaction(service, REGISTER_TRANSACTION, observer.listener))
                throw new IllegalStateException("ASP listener registration rejected");
            observer.registered = true;
            return observer;
        } catch (Exception error) {
            observer.listener.deactivate();
            service.unlinkToDeath(observer.deathRecipient, 0);
            throw error;
        }
    }

    private static boolean listenerTransaction(IBinder service, int code, IBinder listener)
            throws RemoteException {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(SERVICE_DESCRIPTOR);
            data.writeStrongBinder(listener);
            // The native stock proxy sends this as a void transaction and
            // does not read a reply. Match the already proven passive probe.
            return service.transact(code, data, reply, 0);
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    @Override public synchronized void close() {
        listener.deactivate();
        if (registered) {
            try { listenerTransaction(service, UNREGISTER_TRANSACTION, listener); }
            catch (RemoteException ignored) { /* Service death also removes the binder client. */ }
            registered = false;
        }
        service.unlinkToDeath(deathRecipient, 0);
    }
}
