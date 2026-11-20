package com.mcpscanner.client;

import com.mcpscanner.mcp.BoundedBodyReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static com.mcpscanner.testutil.AwaitedFutures.doneWithin;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SseReplyReaderTest {
    @Test
    void oversizedUnterminatedLineStopsBeforeReadingTheWholeStream() {
        AtomicBoolean closed = new AtomicBoolean();
        AtomicInteger bytesRead = new AtomicInteger();
        InputStream stream = new InputStream() {
            private int remaining = BoundedBodyReader.MAX_RESPONSE_BYTES * 2;
            @Override public int read() {
                bytesRead.incrementAndGet();
                return remaining-- > 0 ? 'x' : -1;
            }
            @Override public void close() { closed.set(true); }
        };
        ThreadPoolExecutor executor = executor();
        try (SseReplyReader reader = new SseReplyReader(stream, executor, Duration.ofSeconds(5))) {
            assertThatThrownBy(reader::nextEvent)
                    .hasRootCauseMessage("SSE event exceeded response bound");
            assertThat(closed).isTrue();
            assertThat(bytesRead.get()).isLessThanOrEqualTo(BoundedBodyReader.MAX_RESPONSE_BYTES + 8192);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void heartbeatsDoNotExtendTheReplyDeadline() throws Exception {
        PipedInputStream stream = new PipedInputStream();
        PipedOutputStream output = new PipedOutputStream(stream);
        var heartbeats = Executors.newSingleThreadScheduledExecutor();
        ThreadPoolExecutor executor = executor();
        try (output; SseReplyReader reader = new SseReplyReader(stream, executor, Duration.ofMillis(150))) {
            heartbeats.scheduleAtFixedRate(() -> {
                try {
                    output.write(": heartbeat\n\n".getBytes(StandardCharsets.UTF_8));
                    output.flush();
                } catch (IOException ignored) {
                }
            }, 0, 20, TimeUnit.MILLISECONDS);
            CompletableFuture<?> wait = CompletableFuture.runAsync(() -> {
                while (reader.nextEvent() != null) { }
            });
            assertThatThrownBy(doneWithin(wait, Duration.ofSeconds(1))::join)
                    .hasStackTraceContaining("SSE reply wait timed out");
        } finally {
            heartbeats.shutdownNow();
            executor.shutdownNow();
        }
    }

    @Test
    void multibyteUtf8CountsTowardTheByteLimit() {
        byte[] payload = "é".repeat(BoundedBodyReader.MAX_RESPONSE_BYTES / 2 + 1)
                .getBytes(StandardCharsets.UTF_8);
        ThreadPoolExecutor executor = executor();
        try (SseReplyReader reader = new SseReplyReader(new ByteArrayInputStream(payload), executor,
                Duration.ofSeconds(5))) {
            assertThatThrownBy(reader::nextEvent).hasRootCauseMessage("SSE event exceeded response bound");
        } finally {
            executor.shutdownNow();
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"\n", "\r", "\r\n"})
    void newlineFormatsPreserveConsecutiveEvents(String newline) {
        String frames = "data: café" + newline + newline + "data: second" + newline + newline;
        ThreadPoolExecutor executor = executor();
        try (SseReplyReader reader = new SseReplyReader(
                new ByteArrayInputStream(frames.getBytes(StandardCharsets.UTF_8)), executor, Duration.ofSeconds(1))) {
            assertThat(reader.nextEvent()).isEqualTo("data: café\n\n");
            assertThat(reader.nextEvent()).isEqualTo("data: second\n\n");
            assertThat(reader.nextEvent()).isNull();
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void eachFrameKeepsTheBytesItWasReadFrom() {
        String first = "id: 4\r\nevent: message\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\n";
        String second = ": ping\r\n\r\n";
        ThreadPoolExecutor executor = executor();
        try (SseReplyReader reader = new SseReplyReader(new ByteArrayInputStream(
                (first + second).getBytes(StandardCharsets.UTF_8)), executor, Duration.ofSeconds(1))) {
            assertThat(reader.nextFrame().bytes()).isEqualTo(first.getBytes(StandardCharsets.UTF_8));
            assertThat(reader.nextFrame().bytes()).isEqualTo(second.getBytes(StandardCharsets.UTF_8));
            assertThat(reader.nextFrame()).isNull();
        } finally {
            executor.shutdownNow();
        }
    }

    private static ThreadPoolExecutor executor() {
        return new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(1));
    }
}
