package com.mcpscanner.http.evidence;

import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

public final class BodyCapture extends FilterInputStream {

    private final ByteArrayOutputStream copy = new ByteArrayOutputStream();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final int limit;
    private final Consumer<BodyCapture> onClose;
    private boolean truncated;

    public BodyCapture(InputStream body, int limit) {
        this(body, limit, ignored -> { });
    }

    public BodyCapture(InputStream body, int limit, Consumer<BodyCapture> onClose) {
        super(body);
        this.limit = limit;
        this.onClose = onClose;
    }

    @Override
    public int read() throws IOException {
        int next = super.read();
        if (next >= 0) {
            keep(new byte[] {(byte) next}, 0, 1);
        }
        return next;
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        int count = super.read(buffer, offset, length);
        if (count > 0) {
            keep(buffer, offset, count);
        }
        return count;
    }

    @Override
    public void close() throws IOException {
        try {
            super.close();
        } finally {
            if (closed.compareAndSet(false, true)) {
                onClose.accept(this);
            }
        }
    }

    public synchronized byte[] captured() {
        return copy.toByteArray();
    }

    public synchronized boolean truncated() {
        return truncated;
    }

    public WireRecord completing(WireRecord wire) {
        return wire.withBodyAsRead(captured(), truncated());
    }

    private synchronized void keep(byte[] buffer, int offset, int count) {
        int kept = Math.min(count, limit - copy.size());
        copy.write(buffer, offset, kept);
        truncated |= kept < count;
    }
}
