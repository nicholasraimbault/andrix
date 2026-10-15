// SPDX-License-Identifier: Apache-2.0
package android.content;

import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import java.io.FileNotFoundException;
import java.util.ArrayList;

/**
 * Host model stub of ContentProvider: every public overridable method of the pinned SDK's class
 * that reads or writes data, with the platform's default behavior where a subclass does not
 * override it. The model calls the entry points directly, as ContentProvider's Transport does
 * after its own permission check; for a caller whose read permission failed, the Transport still
 * calls query to learn the columns.
 */
public abstract class ContentProvider {
    private final Context context = new Context();

    public final Context getContext() {
        return context;
    }

    public abstract boolean onCreate();

    public abstract Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
            String sortOrder);

    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder,
            CancellationSignal signal) {
        return query(uri, projection, selection, selectionArgs, sortOrder);
    }

    public Cursor query(Uri uri, String[] projection, Bundle queryArgs, CancellationSignal signal) {
        return query(uri, projection, null, null, null, signal);
    }

    public abstract String getType(Uri uri);

    public String getTypeAnonymous(Uri uri) {
        return getType(uri);
    }

    public String[] getStreamTypes(Uri uri, String mimeTypeFilter) {
        return null;
    }

    public abstract Uri insert(Uri uri, ContentValues values);

    public Uri insert(Uri uri, ContentValues values, Bundle extras) {
        return insert(uri, values);
    }

    public int bulkInsert(Uri uri, ContentValues[] values) {
        for (ContentValues v : values) insert(uri, v);
        return values.length;
    }

    public abstract int update(Uri uri, ContentValues values, String selection, String[] selectionArgs);

    public int update(Uri uri, ContentValues values, Bundle extras) {
        return update(uri, values, null, null);
    }

    public abstract int delete(Uri uri, String selection, String[] selectionArgs);

    public int delete(Uri uri, Bundle extras) {
        return delete(uri, null, null);
    }

    public ContentProviderResult[] applyBatch(ArrayList<ContentProviderOperation> operations)
            throws OperationApplicationException {
        return new ContentProviderResult[0];
    }

    public ContentProviderResult[] applyBatch(String authority, ArrayList<ContentProviderOperation> operations)
            throws OperationApplicationException {
        return applyBatch(operations);
    }

    public Bundle call(String method, String arg, Bundle extras) {
        return null;
    }

    public Bundle call(String authority, String method, String arg, Bundle extras) {
        return call(method, arg, extras);
    }

    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        throw new FileNotFoundException("no files");
    }

    public ParcelFileDescriptor openFile(Uri uri, String mode, CancellationSignal signal)
            throws FileNotFoundException {
        return openFile(uri, mode);
    }

    public AssetFileDescriptor openAssetFile(Uri uri, String mode) throws FileNotFoundException {
        openFile(uri, mode);
        return new AssetFileDescriptor();
    }

    public AssetFileDescriptor openAssetFile(Uri uri, String mode, CancellationSignal signal)
            throws FileNotFoundException {
        return openAssetFile(uri, mode);
    }

    public AssetFileDescriptor openTypedAssetFile(Uri uri, String mimeTypeFilter, Bundle opts)
            throws FileNotFoundException {
        return openAssetFile(uri, "r");
    }

    public AssetFileDescriptor openTypedAssetFile(Uri uri, String mimeTypeFilter, Bundle opts,
            CancellationSignal signal) throws FileNotFoundException {
        return openTypedAssetFile(uri, mimeTypeFilter, opts);
    }

    public Uri canonicalize(Uri uri) {
        return null;
    }

    public Uri uncanonicalize(Uri uri) {
        return uri;
    }

    public boolean refresh(Uri uri, Bundle extras, CancellationSignal signal) {
        return false;
    }
}
