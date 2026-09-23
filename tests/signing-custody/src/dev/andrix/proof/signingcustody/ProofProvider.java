// SPDX-License-Identifier: Apache-2.0
package dev.andrix.proof.signingcustody;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.util.Base64;

import org.json.JSONObject;
import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Shell only lab transport. Its existence is not an owner administration API. */
public final class ProofProvider extends ContentProvider {
    static final String AUTHORITY = "dev.andrix.proof.signingcustody";
    private ProofBroker broker;

    @Override public boolean onCreate() {
        broker = ProofBroker.get(getContext());
        return true;
    }

    private int enforceLabCaller() {
        int caller = Binder.getCallingUid();
        if (caller != 2000 || android.os.Process.myUid() / 100000 != 0
                || !("userdebug".equals(Build.TYPE) || "eng".equals(Build.TYPE))
                || !Build.FINGERPRINT.startsWith("Andrix/andrix_gos_cf_arm64_only_phone/")) {
            throw new SecurityException("lab shell on selected user0 build required");
        }
        return caller;
    }

    private static void fields(Bundle extras, String... names) {
        Set<String> expected = new HashSet<>(Arrays.asList(names));
        Set<String> actual = extras == null ? new HashSet<>() : extras.keySet();
        if (!actual.equals(expected)) throw new IllegalArgumentException("unexpected request fields");
    }

    @Override public Bundle call(String method, String arg, Bundle extras) {
        int caller = enforceLabCaller(); // Before parsing any caller supplied input.
        long identity = Binder.clearCallingIdentity();
        try {
            JSONObject result;
            switch (method) {
                case "status":
                    fields(extras); result = broker.status(); break;
                case "configure":
                    fields(extras, "certificate_sha256", "spki_sha256");
                    result = broker.configure(extras.getString("certificate_sha256"),
                            extras.getString("spki_sha256")); break;
                case "request":
                    fields(extras, "purpose", "certificate_sha256", "payload_base64");
                    String encoded = extras.getString("payload_base64");
                    if (encoded == null || encoded.length() > 87384) {
                        throw new IllegalArgumentException("payload bound");
                    }
                    byte[] payload = Base64.decode(encoded, Base64.NO_WRAP);
                    if (!Base64.encodeToString(payload, Base64.NO_WRAP).equals(encoded)) {
                        throw new IllegalArgumentException("noncanonical payload encoding");
                    }
                    SigningRequest request = broker.request(caller, extras.getString("purpose"),
                            extras.getString("certificate_sha256"), payload);
                    result = broker.requestStatus(request); break;
                case "artifact-request":
                    fields(extras, "request_id", "purpose", "certificate_sha256", "input_sha256", "apk_base64");
                    String encodedApk = extras.getString("apk_base64");
                    if (encodedApk == null || encodedApk.length() > 87384) {
                        throw new IllegalArgumentException("artifact transport bound");
                    }
                    byte[] apk = Base64.decode(encodedApk, Base64.NO_WRAP);
                    if (!Base64.encodeToString(apk, Base64.NO_WRAP).equals(encodedApk)) {
                        throw new IllegalArgumentException("noncanonical artifact encoding");
                    }
                    ArtifactRequest artifact = broker.requestArtifact(caller, extras.getString("request_id"),
                            extras.getString("purpose"), extras.getString("certificate_sha256"),
                            extras.getString("input_sha256"), apk);
                    result = broker.artifactStatus(artifact.id()); break;
                case "artifact-inspect":
                    fields(extras); result = broker.artifactStatus(arg); break;
                case "artifact-output":
                    fields(extras); result = broker.artifactOutput(arg); break;
                case "artifact-cancel":
                    fields(extras); broker.findArtifact(arg); broker.cancel(arg);
                    result = broker.artifactStatus(arg); break;
                case "inspect":
                    fields(extras); result = broker.requestStatus(broker.find(arg)); break;
                case "cancel":
                    fields(extras); SigningRequest cancelled = broker.find(arg); broker.cancel(arg);
                    result = broker.requestStatus(cancelled); break;
                case "cancel-import":
                    fields(extras); result = broker.cancelImport(); break;
                case "without-authentication":
                    fields(extras); result = broker.preAuthenticationNegative(); break;
                case "delete-owned-key":
                    fields(extras); result = broker.deleteKey(); break;
                default:
                    throw new IllegalArgumentException("unsupported lab operation");
            }
            Bundle response = new Bundle(); response.putString("result", result.toString());
            return response;
        } catch (Exception error) {
            Bundle response = new Bundle();
            response.putString("error_class", error.getClass().getName());
            return response;
        } finally {
            Binder.restoreCallingIdentity(identity);
        }
    }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        enforceLabCaller();
        if (!AUTHORITY.equals(uri.getAuthority()) || !"/import".equals(uri.getPath())
                || uri.getQuery() != null || uri.getFragment() != null || !"w".equals(mode)) {
            throw new FileNotFoundException("only the exact lab import stream is supported");
        }
        long identity = Binder.clearCallingIdentity();
        try { return broker.importPipe(); }
        catch (Exception error) { throw new FileNotFoundException("lab import refused"); }
        finally { Binder.restoreCallingIdentity(identity); }
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
            String[] selectionArgs, String sortOrder) {
        enforceLabCaller(); throw new UnsupportedOperationException("call or import only");
    }
    @Override public String getType(Uri uri) {
        enforceLabCaller(); throw new UnsupportedOperationException("call or import only");
    }
    @Override public Uri insert(Uri uri, ContentValues values) {
        enforceLabCaller(); throw new UnsupportedOperationException("call or import only");
    }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) {
        enforceLabCaller(); throw new UnsupportedOperationException("call or import only");
    }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        enforceLabCaller(); throw new UnsupportedOperationException("call or import only");
    }
}
