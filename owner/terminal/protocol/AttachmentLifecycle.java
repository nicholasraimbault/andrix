// SPDX-License-Identifier: Apache-2.0
package dev.andrix.terminal.protocol;

/**
 * One client-side lease, pending or active. This holds no Android authority and
 * performs no I/O. Callers close returned/retired resources outside this lock.
 */
public final class AttachmentLifecycle<T> {
    public static final class Request {
        private boolean cancelled;
        private Request() { }
    }
    private Request preparing;
    private T pending;
    private T active;
    private boolean inputAllowed;

    /** Cancellation does not admit another RPC until its old completion arrives. */
    public synchronized boolean preparing() { return preparing != null; }
    public synchronized Request begin() {
        if (preparing != null || active != null || pending != null) return null;
        preparing = new Request();
        return preparing;
    }
    public synchronized boolean current(Request request) {
        return request != null && preparing == request && !request.cancelled;
    }
    public synchronized boolean retain(Request request, T value) {
        if (value == null || !current(request) || pending != null || active != null) return false;
        pending = value;
        return true;
    }
    public synchronized boolean pending(Request request, T value) {
        return value != null && current(request) && pending == value;
    }
    /** Promotion and input permission are one identity-checked transition. */
    public synchronized boolean promote(Request request, T value, boolean parserAllowsInput) {
        if (!pending(request, value)) return false;
        pending = null;
        preparing = null;
        active = value;
        inputAllowed = parserAllowsInput;
        return true;
    }
    /** Finish only this retired/cancelled/unretained request, never a newer one. */
    public synchronized boolean finish(Request request) {
        if (preparing != request || request == null || pending != null) return false;
        preparing = null;
        return true;
    }
    public synchronized T lease() { return pending != null ? pending : active; }
    public synchronized T active() { return active; }
    public synchronized boolean owns(T value) {
        return value != null && (pending == value || active == value);
    }
    public synchronized boolean inputAllowed(T value) {
        return value != null && active == value && inputAllowed;
    }
    public synchronized void blockInput(T value) {
        if (active == value) inputAllowed = false;
    }
    public synchronized boolean retire(T value) {
        if (value == null) return false;
        if (pending == value) {
            pending = null;
            preparing.cancelled = true;
        } else if (active == value) {
            active = null;
            inputAllowed = false;
        } else return false;
        return true;
    }
    public synchronized T cancel() {
        if (preparing != null) preparing.cancelled = true;
        T value = lease();
        pending = active = null;
        inputAllowed = false;
        return value;
    }
}
