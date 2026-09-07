package dev.andrix.proof.webview;

import android.app.Activity;
import android.content.pm.PackageInfo;
import android.net.http.SslError;
import android.os.Bundle;
import android.os.Looper;
import android.view.ViewGroup;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

/** UI-thread-only WebView state machine. No JS bridge, external HTML, or TLS overrides. */
public final class ProbeActivity extends Activity {
    private static final String LOCAL = "javascript_fetch";
    private static final String BAD = "wrong_host_tls";
    private static final String REJECTED = "wrong_host_tls_rejected";
    private static final String HTML = "<!doctype html><html><head>"
            + "<meta charset='utf-8'><meta name='referrer' content='no-referrer'>"
            + "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
            + "script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'\">"
            + "<title>Andrix WebView probe</title></head><body><p id='proof'></p><script>"
            + "'use strict'; document.getElementById('proof').textContent = String(6 * 7);"
            + "window.__andrixProbe = {state:'pending', dom:document.getElementById('proof').textContent,"
            + "origin:location.origin, base_uri:document.baseURI};"
            + "fetch('/generate_204', {method:'GET', mode:'same-origin', credentials:'omit',"
            + "cache:'no-store', redirect:'error', referrerPolicy:'no-referrer'})"
            + ".then(function(r) { Object.assign(window.__andrixProbe, {state:'complete',"
            + "status:r.status, response_url:r.url, response_type:r.type, redirected:r.redirected}); })"
            + ".catch(function(e) { Object.assign(window.__andrixProbe, {state:'error', error:String(e)}); });"
            + "</script></body></html>";

    private ProbeSession session;
    private WebView webView;
    private String phase = "initialization";
    private boolean attached;
    private boolean webViewCreated;
    private boolean webViewDestroyed;
    private boolean cancellingSsl;
    private final Runnable poll = () -> guarded(this::pollJavaScript);

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        session = WebViewProbeInstrumentation.activeSession;
        if (session == null || session.closing || session.failed.get()) {
            finish(); // No instrumentation, or a late launch after timeout: never browse.
            return;
        }
        if (session.activity != null) {
            session.fail(phase, new IllegalStateException("Unexpected second/recreated Activity"));
            finish();
            return;
        }
        session.activity = this;
        attached = true;
        guarded(this::initialize);
    }

    private boolean active() {
        return attached && !session.closing && !session.failed.get();
    }

    private void guarded(CheckedAction action) {
        if (!active()) {
            return;
        }
        try {
            require(Looper.myLooper() == Looper.getMainLooper(), "WebView callback is not on UI thread");
            action.run();
        } catch (Throwable error) {
            session.fail(phase, error);
        }
    }

    private interface CheckedAction {
        void run() throws Exception;
    }

    private void recordProvider(String point) {
        PackageInfo provider = WebView.getCurrentWebViewPackage();
        session.record("provider", "point", point,
                "package", provider == null ? null : provider.packageName,
                "version_name", provider == null ? null : provider.versionName,
                "version_code", provider == null ? null : provider.getLongVersionCode());
        require(provider != null && session.config.expectedProvider.equals(provider.packageName),
                "Current WebView provider is absent or differs from expected_provider at " + point);
    }

    private void initialize() {
        recordProvider("before_initialization");
        webView = new WebView(this);
        webViewCreated = true;
        setContentView(webView);
        recordProvider("after_initialization");
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        webView.setWebViewClient(new Client());
        session.record("initialization", "webview_created", true,
                "javascript_enabled", settings.getJavaScriptEnabled(),
                "safe_browsing_setting_before", settings.getSafeBrowsingEnabled());
        session.complete("initialization");
        phase = "safe_browsing";
        if (active()) {
            WebView.startSafeBrowsing(getApplicationContext(), available -> guarded(() -> {
                require("safe_browsing".equals(phase), "Duplicate/out-of-order Safe Browsing callback");
                session.record("safe_browsing", "callback_received", true, "callback_value", available,
                        "setting_after", webView.getSettings().getSafeBrowsingEnabled(),
                        "setting_changed_by_probe", false, "protection_verified", false);
                require(available != null, "Null Safe Browsing initialization callback");
                // Either Boolean value is evidence, not proof of a URL-checking backend.
                session.complete("safe_browsing");
                phase = LOCAL;
                if (active()) {
                    webView.loadDataWithBaseURL(session.config.goodOrigin + "/", HTML,
                            "text/html", "UTF-8", session.config.goodOrigin + "/");
                    pollJavaScript();
                }
            }));
        }
    }

    private void pollJavaScript() {
        require(LOCAL.equals(phase), "JavaScript poll outside local-page stage");
        webView.evaluateJavascript("JSON.stringify(window.__andrixProbe || null)", value -> guarded(() -> {
            require(LOCAL.equals(phase), "Late JavaScript callback");
            // An evaluation before the local document is ready may return JSON null.
            // Otherwise evaluateJavascript JSON-encodes our returned JSON string once more.
            Object decoded = value == null ? JSONObject.NULL : new JSONTokener(value).nextValue();
            if (decoded == JSONObject.NULL || "null".equals(decoded)) {
                schedulePoll();
                return;
            }
            require(decoded instanceof String, "JavaScript did not return a JSON string");
            JSONObject js = new JSONObject((String) decoded);
            if ("pending".equals(js.getString("state"))) {
                schedulePoll();
                return;
            }
            session.record(LOCAL, "result", js);
            require("complete".equals(js.getString("state")), "JavaScript fetch failed: " + js);
            require("42".equals(js.getString("dom"))
                    && session.config.goodOrigin.equals(js.getString("origin"))
                    && (session.config.goodOrigin + "/").equals(js.getString("base_uri")),
                    "Local DOM/JavaScript did not execute at the exact good HTTPS origin");
            require(js.getInt("status") == 204 && !js.getBoolean("redirected")
                    && "basic".equals(js.getString("response_type"))
                    && session.config.goodUrl.equals(js.getString("response_url")),
                    "Same-origin fetch requires an actual, unredirected HTTP 204");
            session.complete(LOCAL);
            phase = BAD;
            if (active()) {
                webView.loadUrl(session.config.badUrl);
            }
        }));
    }

    private void schedulePoll() {
        require(session.main.postDelayed(poll, 500), "Main looper refused JavaScript poll");
    }

    private final class Client extends WebViewClient {
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            // App-initiated loads do not use this hook. Reject all page/redirect navigation.
            guarded(() -> {
                session.record("blocked_navigation", "url", request.getUrl().toString());
                throw new IllegalStateException("Unexpected page navigation or redirect");
            });
            return true;
        }

        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            try {
                // Unconditional, even during failure/cleanup or for an unexpected URL/error.
                cancellingSsl = true;
                try {
                    handler.cancel();
                } finally {
                    cancellingSsl = false;
                }
                if (!active()) {
                    return;
                }
                JSONArray codes = new JSONArray();
                for (int code : new int[] {SslError.SSL_NOTYETVALID, SslError.SSL_EXPIRED,
                        SslError.SSL_IDMISMATCH, SslError.SSL_UNTRUSTED,
                        SslError.SSL_DATE_INVALID, SslError.SSL_INVALID}) {
                    if (error.hasError(code)) {
                        codes.put(code);
                    }
                }
                session.record("ssl_error", "stage", phase, "url", error.getUrl(),
                        "primary_error", error.getPrimaryError(), "error_codes", codes,
                        "cancel_returned", true);
                require(BAD.equals(phase) && session.config.badUrl.equals(error.getUrl()),
                        "SSL error outside the exact wrong-host navigation");
                require(error.getPrimaryError() == SslError.SSL_IDMISMATCH
                        && error.hasError(SslError.SSL_IDMISMATCH) && codes.length() == 1,
                        "Need hostname mismatch alone, not expiry, untrusted CA or another TLS failure");
                phase = REJECTED;
                session.complete(BAD);
            } catch (Throwable failure) {
                session.fail(phase, failure);
            }
        }

        @Override
        public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
            guarded(() -> {
                String url = request.getUrl().toString();
                session.record("web_error", "stage", phase, "url", url,
                        "main_frame", request.isForMainFrame(), "code", error.getErrorCode(),
                        "description", error.getDescription().toString());
                // Cancellation may produce a main-frame error, but never counts as TLS proof.
                require((REJECTED.equals(phase) || (BAD.equals(phase) && cancellingSsl))
                        && request.isForMainFrame() && session.config.badUrl.equals(url),
                        "Unexpected WebView network error (generic TLS errors cannot pass)");
            });
        }

        @Override
        public void onReceivedHttpError(WebView view, WebResourceRequest request,
                WebResourceResponse response) {
            guarded(() -> {
                session.record("http_error", "url", request.getUrl().toString(),
                        "status", response.getStatusCode());
                throw new IllegalStateException("Unexpected HTTP error");
            });
        }

        @Override
        public boolean onRenderProcessGone(WebView view, RenderProcessGoneDetail detail) {
            // Handle lifecycle cleanup, but explicitly FAIL rather than concealing the crash.
            session.fail(phase, new IllegalStateException("WebView renderer gone; didCrash="
                    + detail.didCrash() + ", priority=" + detail.rendererPriorityAtExit()));
            releaseWebView();
            return true;
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (webView != null) {
            guarded(webView::onResume);
        }
    }

    @Override
    protected void onPause() {
        if (webView != null) {
            guarded(webView::onPause);
        }
        super.onPause();
    }

    void close() {
        phase = "cleanup";
        releaseWebView();
        finish();
    }

    private void cleanupCall(Runnable action) {
        try {
            action.run();
        } catch (Throwable error) {
            session.fail("cleanup", error);
        }
    }

    private void releaseWebView() {
        session.main.removeCallbacks(poll);
        WebView view = webView;
        webView = null;
        if (view == null) {
            return;
        }
        // Try every cleanup step; each exception is retained as a test failure.
        cleanupCall(view::stopLoading);
        cleanupCall(() -> {
            if (view.getParent() != null) {
                ((ViewGroup) view.getParent()).removeView(view);
            }
        });
        cleanupCall(view::removeAllViews);
        cleanupCall(() -> {
            view.destroy();
            webViewDestroyed = true;
        });
    }

    @Override
    protected void onDestroy() {
        if (!attached) {
            super.onDestroy();
            return;
        }
        if (!session.closing) {
            session.fail(phase, new IllegalStateException("Activity destroyed before requested cleanup"));
        }
        releaseWebView();
        cleanupCall(() -> super.onDestroy());
        session.record("cleanup", "activity_attached", true, "on_destroy_called", true,
                "webview_created", webViewCreated, "webview_destroyed", webViewDestroyed);
        session.cleaned.countDown();
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
