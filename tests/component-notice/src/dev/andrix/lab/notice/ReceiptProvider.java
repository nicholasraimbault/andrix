// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.notice;

import android.content.ContentProvider;
import android.content.ContentProviderOperation;
import android.content.ContentProviderResult;
import android.content.ContentValues;
import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.UserManager;
import java.util.ArrayList;

/**
 * The read only receipt provider. The manifest guards it with DUMP. Every entry point first checks
 * that the Binder caller is the shell user, before it reads an argument; nothing here clears the
 * calling identity. ContentProvider calls query to learn the columns even for a caller whose read
 * permission failed, so the explicit check is what refuses a foreign caller.
 *
 * <p>The one admitted operation is the whole listing of this user's store, one column of lines.
 * Insert, update, delete, batches, calls, every file open, type queries and URI transforms are
 * refused. The provider never writes, so a row can only come from the presentation code.
 */
public final class ReceiptProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
        return true;
    }

    private static void shellCaller() {
        String why = ProviderPolicy.caller(Binder.getCallingUid());
        if (why != null) throw new SecurityException(why);
    }

    private static UnsupportedOperationException refused(String operation) {
        return new UnsupportedOperationException(ProviderPolicy.refused(operation));
    }

    @Override
    public Cursor query(Uri uri, String[] projection, Bundle queryArgs, CancellationSignal signal) {
        shellCaller();
        String why = ProviderPolicy.query(uri == null ? null : uri.toString(), projection,
                queryArgs == null || queryArgs.isEmpty());
        if (why != null) throw new IllegalArgumentException(why);
        Context context = getContext();
        int uid = Process.myUid();
        long serial = context.getSystemService(UserManager.class).getSerialNumberForUser(Process.myUserHandle());
        ReceiptStore.Listing listing = Writer.store(context).list(uid, serial);
        MatrixCursor cursor = new MatrixCursor(new String[] {ProviderPolicy.COLUMN}, listing.lines.size());
        for (String line : listing.lines) cursor.addRow(new Object[] {line});
        return cursor;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        shellCaller();
        throw refused("query with a selection");
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder,
            CancellationSignal signal) {
        shellCaller();
        throw refused("query with a selection");
    }

    @Override
    public String getType(Uri uri) {
        shellCaller();
        throw refused("getType");
    }

    @Override
    public String getTypeAnonymous(Uri uri) {
        shellCaller();
        throw refused("getTypeAnonymous");
    }

    @Override
    public String[] getStreamTypes(Uri uri, String mimeTypeFilter) {
        shellCaller();
        throw refused("getStreamTypes");
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        shellCaller();
        throw refused("insert");
    }

    @Override
    public Uri insert(Uri uri, ContentValues values, Bundle extras) {
        shellCaller();
        throw refused("insert");
    }

    @Override
    public int bulkInsert(Uri uri, ContentValues[] values) {
        shellCaller();
        throw refused("bulkInsert");
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        shellCaller();
        throw refused("update");
    }

    @Override
    public int update(Uri uri, ContentValues values, Bundle extras) {
        shellCaller();
        throw refused("update");
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        shellCaller();
        throw refused("delete");
    }

    @Override
    public int delete(Uri uri, Bundle extras) {
        shellCaller();
        throw refused("delete");
    }

    @Override
    public ContentProviderResult[] applyBatch(ArrayList<ContentProviderOperation> operations) {
        shellCaller();
        throw refused("applyBatch");
    }

    @Override
    public ContentProviderResult[] applyBatch(String authority, ArrayList<ContentProviderOperation> operations) {
        shellCaller();
        throw refused("applyBatch");
    }

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        shellCaller();
        throw refused("call");
    }

    @Override
    public Bundle call(String authority, String method, String arg, Bundle extras) {
        shellCaller();
        throw refused("call");
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) {
        shellCaller();
        throw refused("openFile");
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode, CancellationSignal signal) {
        shellCaller();
        throw refused("openFile");
    }

    @Override
    public AssetFileDescriptor openAssetFile(Uri uri, String mode) {
        shellCaller();
        throw refused("openAssetFile");
    }

    @Override
    public AssetFileDescriptor openAssetFile(Uri uri, String mode, CancellationSignal signal) {
        shellCaller();
        throw refused("openAssetFile");
    }

    @Override
    public AssetFileDescriptor openTypedAssetFile(Uri uri, String mimeTypeFilter, Bundle opts) {
        shellCaller();
        throw refused("openTypedAssetFile");
    }

    @Override
    public AssetFileDescriptor openTypedAssetFile(Uri uri, String mimeTypeFilter, Bundle opts,
            CancellationSignal signal) {
        shellCaller();
        throw refused("openTypedAssetFile");
    }

    @Override
    public Uri canonicalize(Uri uri) {
        shellCaller();
        throw refused("canonicalize");
    }

    @Override
    public Uri uncanonicalize(Uri uri) {
        shellCaller();
        throw refused("uncanonicalize");
    }

    @Override
    public boolean refresh(Uri uri, Bundle extras, CancellationSignal signal) {
        shellCaller();
        throw refused("refresh");
    }
}
