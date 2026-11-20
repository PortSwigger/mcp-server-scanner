package com.mcpscanner.mcp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.function.Supplier;

public final class SseFrameReader {

    public record Limits(long maxLineUnits, long maxFrameUnits, String frameOverflow,
                         long maxTotalUnits, String totalOverflow) {
        public Limits(long maxFrameUnits, String frameOverflow, long maxTotalUnits, String totalOverflow) {
            this(maxFrameUnits, maxFrameUnits, frameOverflow, maxTotalUnits, totalOverflow);
        }

        public static Limits perFrame(long maxFrameUnits, String frameOverflow) {
            return new Limits(maxFrameUnits, frameOverflow, Long.MAX_VALUE, frameOverflow);
        }
    }

    private interface UnitSource {
        int read() throws IOException;
    }

    private interface FrameBuffer {
        void append(int unit);

        String text();
    }

    private interface FrameRecorder {
        FrameRecorder NONE = new FrameRecorder() {
        };

        default void restart() {
        }

        default void dropLeadingLineFeed() {
        }

        default boolean absorbedLineFeed() throws IOException {
            return false;
        }

        default byte[] bytes() {
            return new byte[0];
        }
    }

    private final UnitSource source;
    private final Supplier<FrameBuffer> buffers;
    private final Limits limits;
    private final FrameRecorder recorder;
    private boolean skipLineFeed;
    private long totalUnits;

    private SseFrameReader(UnitSource source, Supplier<FrameBuffer> buffers, Limits limits, FrameRecorder recorder) {
        this.source = source;
        this.buffers = buffers;
        this.limits = Objects.requireNonNull(limits, "limits");
        this.recorder = recorder;
    }

    public static SseFrameReader over(InputStream stream, Limits limits) {
        return new SseFrameReader(stream::read, ByteFrameBuffer::new, limits, FrameRecorder.NONE);
    }

    public static SseFrameReader over(Reader reader, Limits limits) {
        return new SseFrameReader(reader::read, CharFrameBuffer::new, limits, FrameRecorder.NONE);
    }

    public static SseFrameReader capturing(InputStream stream, Limits limits) {
        RecordedBytes recorded = new RecordedBytes(new PushbackInputStream(stream));
        return new SseFrameReader(recorded, ByteFrameBuffer::new, limits, recorded);
    }

    public RawSseFrame nextRawFrame() throws IOException {
        String text = nextFrame();
        return text == null ? null : new RawSseFrame(text, recorder.bytes());
    }

    public String nextFrame() throws IOException {
        recorder.restart();
        FrameBuffer frame = buffers.get();
        long frameUnits = 0;
        long lineUnits = 0;
        int unit;
        while ((unit = readUnit()) != -1) {
            boolean lineEnd = unit == '\r' || unit == '\n';
            frame.append(lineEnd ? '\n' : unit);
            countUnit(++frameUnits, lineEnd ? 0 : ++lineUnits);
            if (lineEnd) {
                skipLineFeed = unit == '\r';
                if (lineUnits == 0) {
                    skipLineFeed = skipLineFeed && !recorder.absorbedLineFeed();
                    return frame.text();
                }
                lineUnits = 0;
            }
        }
        return null;
    }

    public InputStream remainder(InputStream original) {
        return new RemainderStream(original);
    }

    private int readUnit() throws IOException {
        int unit = source.read();
        if (skipLineFeed) {
            skipLineFeed = false;
            if (unit == '\n') {
                recorder.dropLeadingLineFeed();
                unit = source.read();
            }
        }
        return unit;
    }

    private void countUnit(long frameUnits, long lineUnits) throws IOException {
        if (++totalUnits > limits.maxTotalUnits()) {
            throw new IOException(limits.totalOverflow());
        }
        if (frameUnits > limits.maxFrameUnits() || lineUnits > limits.maxLineUnits()) {
            throw new IOException(limits.frameOverflow());
        }
    }

    private final class RemainderStream extends InputStream {
        private final InputStream original;

        private RemainderStream(InputStream original) {
            this.original = original;
        }

        @Override
        public int read() throws IOException {
            return readUnit();
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, bytes.length);
            if (length == 0) {
                return 0;
            }
            if (!skipLineFeed) {
                return original.read(bytes, offset, length);
            }
            int first = readUnit();
            if (first == -1) {
                return -1;
            }
            bytes[offset] = (byte) first;
            return 1;
        }

        @Override
        public int available() throws IOException {
            return original.available();
        }

        @Override
        public void close() throws IOException {
            original.close();
        }
    }

    private static final class RecordedBytes implements UnitSource, FrameRecorder {
        private final PushbackInputStream stream;
        private final ByteArrayOutputStream recorded = new ByteArrayOutputStream();

        private RecordedBytes(PushbackInputStream stream) {
            this.stream = stream;
        }

        @Override
        public int read() throws IOException {
            int unit = stream.read();
            if (unit != -1) {
                recorded.write(unit);
            }
            return unit;
        }

        @Override
        public void restart() {
            recorded.reset();
        }

        @Override
        public void dropLeadingLineFeed() {
            if (recorded.size() == 1) {
                recorded.reset();
            }
        }

        @Override
        public boolean absorbedLineFeed() throws IOException {
            if (stream.available() == 0) {
                return false;
            }
            int next = stream.read();
            if (next == '\n') {
                recorded.write(next);
                return true;
            }
            if (next != -1) {
                stream.unread(next);
            }
            return false;
        }

        @Override
        public byte[] bytes() {
            return recorded.toByteArray();
        }
    }

    private static final class ByteFrameBuffer implements FrameBuffer {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        @Override
        public void append(int unit) {
            bytes.write(unit);
        }

        @Override
        public String text() {
            return bytes.toString(StandardCharsets.UTF_8);
        }
    }

    private static final class CharFrameBuffer implements FrameBuffer {
        private final StringBuilder chars = new StringBuilder();

        @Override
        public void append(int unit) {
            chars.append((char) unit);
        }

        @Override
        public String text() {
            return chars.toString();
        }
    }
}
