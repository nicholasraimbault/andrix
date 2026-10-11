// SPDX-License-Identifier: Apache-2.0
package dev.andrix.lab.component;

import dev.andrix.lab.component.LabProtocol.Message;
import dev.andrix.lab.component.LabProtocol.ProtocolError;
import dev.andrix.lab.component.LabProtocol.Status;
import dev.andrix.lab.component.LabProtocol.Type;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * One coordinator generation's private channel to the broker: one request at a time, each answered
 * by exactly one reply. Every request has a fresh random ID and the admitted manifest digest. A
 * reply must be well formed, of the request's reply type, and repeat its ID and the manifest. A
 * channel that breaks any of these, or ends, throws {@link ChannelLost}: the generation cannot
 * know what the broker did, so it must end without another request.
 */
public final class BrokerChannel {
    /** How a channel moves whole frames. Production uses the process's own standard streams. */
    public interface Transport {
        /** Sends one request frame and returns the one reply frame. */
        byte[] exchange(byte[] request) throws IOException;
    }

    /** The channel broke or the broker broke the protocol. Nothing further may be sent. */
    public static final class ChannelLost extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public ChannelLost(String reason, Throwable cause) { super(reason, cause); }
    }

    /** A transport over a stream pair, such as the standard input and output a broker created. */
    public static Transport streams(InputStream in, OutputStream out) {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(out, "out");
        return request -> {
            out.write(request);
            out.flush();
            byte[] header = readExactly(in, 12);
            int length = LabProtocol.frameLength(header);
            byte[] frame = new byte[length];
            System.arraycopy(header, 0, frame, 0, 12);
            byte[] rest = readExactly(in, length - 12);
            System.arraycopy(rest, 0, frame, 12, rest.length);
            return frame;
        };
    }

    private static byte[] readExactly(InputStream in, int count) throws IOException {
        byte[] out = new byte[count];
        int at = 0;
        while (at < count) {
            int n = in.read(out, at, count - at);
            if (n < 0) throw new EOFException("the broker's stream ended inside a reply");
            at += n;
        }
        return out;
    }

    private final Transport transport;
    private final String manifest;
    private final SecureRandom random;
    private final Set<String> used = new HashSet<>();
    private boolean lost;

    public BrokerChannel(Transport transport, String manifest, SecureRandom random) {
        this.transport = Objects.requireNonNull(transport, "transport");
        LabProtocol.checkHex(manifest, 32, "manifest", false);
        this.manifest = manifest;
        this.random = Objects.requireNonNull(random, "random");
    }

    public String manifest() { return manifest; }

    /** A fresh request ID, nonzero and never used on this channel. */
    String freshId() {
        while (true) {
            byte[] bytes = new byte[16];
            random.nextBytes(bytes);
            String id = LabProtocol.hex(bytes);
            if (!id.equals(LabProtocol.ZERO_ID) && used.add(id)) return id;
        }
    }

    /** A builder of a request of one type with a fresh ID and this channel's manifest. */
    public LabProtocol.Builder request(Type type) {
        if (!type.request()) throw new IllegalArgumentException("not a request type");
        return Message.of(type, freshId(), manifest);
    }

    /**
     * Sends one request and returns its reply. A REFUSED reply is returned like any other: the
     * caller decides, and every caller in the bridge treats it as fatal.
     */
    public Message call(Message request) {
        if (lost) throw new ChannelLost("the channel was lost before", null);
        if (!request.manifest.equals(manifest)) throw new IllegalArgumentException("another manifest");
        byte[] data = LabProtocol.encode(request);
        Message reply;
        try {
            reply = LabProtocol.decode(transport.exchange(data));
        } catch (IOException | ProtocolError error) {
            lost = true;
            throw new ChannelLost("the broker channel failed: " + error.getMessage(), error);
        }
        if (reply.type != request.type.reply() || !reply.request.equals(request.request)
                || !reply.manifest.equals(manifest)) {
            lost = true;
            throw new ChannelLost("a reply that does not answer its request", null);
        }
        return reply;
    }

    /** Whether a reply refused its request, which no caller survives. */
    static boolean refused(Message reply) { return reply.status() == Status.REFUSED; }
}
