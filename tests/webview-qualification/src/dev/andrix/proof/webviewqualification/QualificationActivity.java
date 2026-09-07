package dev.andrix.proof.webviewqualification;

import android.app.Activity;
import android.os.Bundle;
import android.view.ViewGroup;
import android.webkit.WebView;

/** Initialization only, on the main thread. No page loads or permission requests. */
public final class QualificationActivity extends Activity {
    private Session session;
    private WebView webView;
    private boolean closeRequested;

    @Override
    protected void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        session = QualificationInstrumentation.activeSession;
        if (session == null) {
            finish();
            return;
        }
        if (session.activity != null) {
            session.fail("activity_create", new IllegalStateException("Duplicate Activity"));
            session = null;
            finish();
            return;
        }
        session.activity = this;
        if (session.closing || session.failed.get()) {
            close();
            return;
        }
        try {
            session.requireRunning();
            Arguments.check(session.args.configMode(), "Activity is only for self-target config modes");
            Pins.selectedProvider(session, "before_initialization");
            webView = new WebView(this);
            setContentView(webView);
            // Chromium's public entry is a filtered support-library loader.
            // Load only its permitted glue entry, then inspect that Class's
            // defining loader through public java.lang.Class metadata. This
            // neither reads Android private fields nor creates a duplicate DEX
            // loader with different static state. Internal reads remain pinned
            // third-party white-box observations, not an application API promise.
            ClassLoader supportLoader = WebView.getWebViewClassLoader();
            Arguments.check(supportLoader != null, "No public support-library class loader");
            Class<?> glue = Class.forName(
                    "org.chromium.support_lib_glue.SupportLibReflectionUtil", false, supportLoader);
            ClassLoader loader = glue.getClassLoader();
            Pins.selectedProvider(session, "after_initialization");
            session.requireRunning();
            Arguments.check(loader != null, "No defining provider class loader");
            session.record("webview_initialized", "uid", android.os.Process.myUid(),
                    "public_loader_class", supportLoader.getClass().getName(),
                    "glue_entry", glue.getName(), "loader_class", loader.getClass().getName(),
                    "page_loaded", false);
            session.initialized.complete(loader);
        } catch (Throwable error) {
            session.fail("webview_initialization", error);
            session.initialized.completeExceptionally(error);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (webView != null) {
            try {
                webView.onResume();
            } catch (Throwable error) {
                session.fail("activity_resume", error);
            }
        }
    }

    @Override
    protected void onPause() {
        if (webView != null) {
            try {
                webView.onPause();
            } catch (Throwable error) {
                session.fail("activity_pause", error);
            }
        }
        super.onPause();
    }

    void close() {
        closeRequested = true;
        releaseWebView();
        finish(); // Only onDestroy acknowledges lifecycle cleanup.
    }

    private void releaseWebView() {
        if (webView == null) {
            return;
        }
        WebView view = webView;
        webView = null;
        cleanupCall(view::stopLoading);
        cleanupCall(() -> {
            if (view.getParent() instanceof ViewGroup) {
                ((ViewGroup) view.getParent()).removeView(view);
            }
        });
        cleanupCall(view::removeAllViews);
        cleanupCall(view::destroy);
        session.record("webview_destroy_requested");
    }

    private void cleanupCall(Runnable action) {
        try {
            action.run();
        } catch (Throwable error) {
            session.fail("webview_cleanup", error);
        }
    }

    @Override
    protected void onDestroy() {
        try {
            if (session != null) {
                if (!closeRequested) {
                    session.fail("activity_destroy", new IllegalStateException("Unexpected destruction"));
                }
                releaseWebView();
            }
        } finally {
            try {
                super.onDestroy();
            } finally {
                if (session != null) {
                    session.record("activity_destroyed", "close_requested", closeRequested);
                    session.destroyed.complete(null);
                }
            }
        }
    }
}
