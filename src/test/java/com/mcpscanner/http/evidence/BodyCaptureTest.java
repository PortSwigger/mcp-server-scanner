package com.mcpscanner.http.evidence;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class BodyCaptureTest {

    @Test
    void keepsEveryByteTheCallerReadWithinTheLimit() throws Exception {
        BodyCapture capture = new BodyCapture(stream("hello"), 16);

        assertThat(capture.readAllBytes()).isEqualTo(bytes("hello"));
        assertThat(capture.captured()).isEqualTo(bytes("hello"));
        assertThat(capture.truncated()).isFalse();
    }

    @Test
    void keepsOnlyWhatTheCallerReadSoFar() throws Exception {
        BodyCapture capture = new BodyCapture(stream("hello"), 16);

        capture.read();
        capture.read(new byte[2], 0, 2);

        assertThat(capture.captured()).isEqualTo(bytes("hel"));
    }

    @Test
    void flagsTruncationOnceTheCallerReadsPastTheLimit() throws Exception {
        BodyCapture capture = new BodyCapture(stream("hello"), 3);

        assertThat(capture.readAllBytes()).isEqualTo(bytes("hello"));
        assertThat(capture.captured()).isEqualTo(bytes("hel"));
        assertThat(capture.truncated()).isTrue();
    }

    @Test
    void aBodyExactlyAtTheLimitIsNotTruncated() throws Exception {
        BodyCapture capture = new BodyCapture(stream("hel"), 3);

        capture.readAllBytes();

        assertThat(capture.truncated()).isFalse();
    }

    @Test
    void reportsItselfOnceWhenClosed() throws Exception {
        AtomicReference<byte[]> reported = new AtomicReference<>();
        BodyCapture capture = new BodyCapture(stream("hello"), 16, closed -> reported.set(closed.captured()));

        capture.readNBytes(2);
        capture.close();
        reported.set(null);
        capture.close();

        assertThat(reported.get()).isNull();
    }

    @Test
    void reportsWhatWasReadWhenClosed() throws Exception {
        AtomicReference<byte[]> reported = new AtomicReference<>();
        BodyCapture capture = new BodyCapture(stream("hello"), 16, closed -> reported.set(closed.captured()));

        capture.readNBytes(2);
        capture.close();

        assertThat(reported.get()).isEqualTo(bytes("he"));
    }

    private static ByteArrayInputStream stream(String text) {
        return new ByteArrayInputStream(bytes(text));
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
