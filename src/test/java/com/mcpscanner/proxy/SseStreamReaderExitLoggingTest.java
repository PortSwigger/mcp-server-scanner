package com.mcpscanner.proxy;

import com.mcpscanner.logging.McpEventLog;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class SseStreamReaderExitLoggingTest {

    private final McpEventLog eventLog = new McpEventLog(null);
    private final SseReplyDispatcher replies = new SseReplyDispatcher(eventLog, () -> 1024);
    private final SseStreamReader reader = new SseStreamReader("test-reader", replies, eventLog,
            new SessionLifecycle(), data -> false);

    @Test
    void aRequestedCloseWithNoWaitersIsLoggedAtDebug() throws IOException {
        BlockingStream upstream = new BlockingStream();
        reader.adopt(upstream);
        reader.start();
        upstream.awaitReading();

        reader.stop();

        assertThat(awaitExitEntry().level()).isEqualTo(McpEventLog.Level.DEBUG);
    }

    @Test
    void aRequestedCloseThatFailsWaitersIsLoggedAtWarn() throws IOException {
        BlockingStream upstream = new BlockingStream();
        reader.adopt(upstream);
        reader.start();
        upstream.awaitReading();
        CompletableFuture<StreamedReply> waiting = replies.expect("7");

        reader.stop();

        assertThat(awaitExitEntry().level()).isEqualTo(McpEventLog.Level.WARN);
        assertThat(waiting).isCompletedExceptionally();
    }

    @Test
    void anUnexpectedEndOfStreamIsLoggedAtWarn() throws IOException {
        reader.adopt(new ByteArrayInputStream("".getBytes(UTF_8)));
        reader.start();

        assertThat(awaitExitEntry().level()).isEqualTo(McpEventLog.Level.WARN);
    }

    private McpEventLog.LogEntry awaitExitEntry() {
        return await().until(() -> eventLog.snapshot().stream()
                .filter(entry -> entry.message().startsWith("SSE reader thread exited"))
                .findFirst().orElse(null), entry -> entry != null);
    }

    private static final class BlockingStream extends InputStream {

        private final CountDownLatch reading = new CountDownLatch(1);
        private final CountDownLatch closed = new CountDownLatch(1);

        void awaitReading() {
            await().until(() -> reading.getCount() == 0);
        }

        @Override
        public int read() throws IOException {
            return read(new byte[1], 0, 1);
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            reading.countDown();
            try {
                closed.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            throw new IOException("closed");
        }

        @Override
        public void close() {
            closed.countDown();
        }
    }
}
