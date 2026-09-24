// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.nativeruntime;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.SystemClock;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

/** Finite component characterization, not ordinary work entry or a foreground test. */
public final class RuntimeInstrumentation extends Instrumentation {
    private String nonce;
    private int sequence;
    private final ArrayList<Connection> connections = new ArrayList<>();

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        nonce = RuntimeProfile.nonce(arguments == null ? null : arguments.getString("nonce"));
        if (nonce.length() > 60) throw new IllegalArgumentException("nonce too long for suffix");
        start();
    }

    private void event(String phase, JSONObject details) throws Exception {
        JSONObject value = new JSONObject().put("version", 1).put("seq", ++sequence)
                .put("nonce", nonce).put("phase", phase)
                .put("elapsed_ms", SystemClock.elapsedRealtime()).put("details", details);
        Bundle output = new Bundle();
        output.putString("runtime_event", value.toString());
        sendStatus(0, output);
    }

    private final class Connection implements ServiceConnection {
        final String kind;
        final String requestNonce;
        final ComponentName component;
        final CountDownLatch ready = new CountDownLatch(1);
        volatile IBinder endpoint;
        volatile String failure;
        volatile boolean closing;
        boolean accepted;
        Connection(String kind, String className) {
            this.kind = kind;
            requestNonce = nonce + (kind.equals("native") ? "_n" : "_m");
            component = new ComponentName(RuntimeProfile.PACKAGE, className);
        }
        @Override public void onServiceConnected(ComponentName name, IBinder service) {
            if (!component.equals(name) || service == null || endpoint != null)
                failure = "unexpected service connection";
            else endpoint = service;
            ready.countDown();
        }
        @Override public void onServiceDisconnected(ComponentName name) {
            if (!closing) failure = "service disconnected";
            ready.countDown();
        }
        @Override public void onBindingDied(ComponentName name) {
            if (!closing) failure = "binding died";
            ready.countDown();
        }
        @Override public void onNullBinding(ComponentName name) {
            failure = "null binding";
            ready.countDown();
        }
        JSONObject bindAndQuery() throws Exception {
            Intent intent = new Intent().setComponent(component).setAction(requestNonce);
            accepted = getTargetContext().bindService(intent, this, Context.BIND_AUTO_CREATE);
            if (!accepted) throw new IllegalStateException(kind + " bind refused");
            if (!ready.await(25, TimeUnit.SECONDS) || failure != null || endpoint == null)
                throw new IllegalStateException(kind + " bind incomplete: " + failure);
            Parcel request = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                request.writeInterfaceToken(RuntimeProfile.DESCRIPTOR);
                if (!endpoint.transact(RuntimeProfile.QUERY, request, reply, 0))
                    throw new IllegalStateException(kind + " query refused");
                String text = reply.readString();
                if (text == null || text.length() > 65536 || reply.dataAvail() != 0)
                    throw new IllegalStateException(kind + " invalid reply");
                JSONObject value = new JSONObject(text);
                if (value.getInt("version") != 1 || !kind.equals(value.getString("kind"))
                        || !requestNonce.equals(value.getString("nonce")))
                    throw new IllegalStateException(kind + " reply identity");
                return value;
            } finally { reply.recycle(); request.recycle(); }
        }
        boolean close() {
            closing = true;
            endpoint = null;
            if (accepted) {
                // Return is not acknowledgement of the remote onDestroy callback.
                getTargetContext().unbindService(this);
                accepted = false;
                return true;
            }
            return false;
        }
    }

    @Override public void onStart() {
        boolean passed = false;
        String errorClass = "", message = "";
        try {
            event("controller", RuntimeProfile.capture(getTargetContext(), "controller", nonce,
                    SystemClock.elapsedRealtime()));
            Connection managed = new Connection("managed", RuntimeProfile.PACKAGE + ".ManagedProbeService");
            connections.add(managed);
            JSONObject m = managed.bindAndQuery();
            event("managed", m);
            Connection nativeService = new Connection("native", RuntimeProfile.PACKAGE + ".NativeProbeService");
            connections.add(nativeService);
            JSONObject n = nativeService.bindAndQuery();
            event("native", n);
            event("observing", new JSONObject().put("duration_ms", 30000));
            for (int i = 0; i < 15; ++i) {
                Thread.sleep(2000);
                for (Connection c : connections)
                    if (c.failure != null) throw new IllegalStateException(c.kind + ": " + c.failure);
                event("heartbeat", new JSONObject().put("index", i));
            }
            passed = true;
        } catch (Exception error) {
            errorClass = error.getClass().getName();
            message = String.valueOf(error.getMessage());
            if (message.length() > 512) message = message.substring(0, 512);
        } finally {
            for (int i = connections.size() - 1; i >= 0; --i) {
                Connection c = connections.get(i);
                try {
                    event("unbind_begin", new JSONObject().put("kind", c.kind));
                    boolean called = c.close();
                    event("unbind_returned", new JSONObject().put("kind", c.kind).put("called", called));
                } catch (Exception error) {
                    passed = false;
                    errorClass = error.getClass().getName();
                    message = "unbind outcome unresolved";
                }
            }
            try {
                // Normal instrumentation finish force stops the target package. Keep a
                // separate window for genuine unbind/destroy callbacks before finish.
                event("awaiting_destroy", new JSONObject().put("duration_ms", 10000));
                Thread.sleep(10000);
                event("complete", new JSONObject().put("controller_passed", passed)
                        .put("error_class", errorClass).put("message", message)
                        .put("remote_retirement_requires_observation", true));
            } catch (Exception error) { passed = false; }
            Bundle result = new Bundle();
            result.putString("runtime_result", passed ? "controller_complete" : "controller_failed");
            finish(passed ? Activity.RESULT_OK : Activity.RESULT_CANCELED, result);
        }
    }
}
