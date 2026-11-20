package com.mcpscanner.mcp;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class RawSseFrameReaderTest {

    private static final SseFrameReader.Limits GENEROUS = SseFrameReader.Limits.perFrame(64 * 1024, "frame too large");

    @Test
    void keepsEachFramesBytesExactlyAsReadWithItsIdEventAndMultiLineData() throws IOException {
        String first = ": keep-alive\n\n";
        String second = "id: 7\nevent: message\ndata: {\"a\":\ndata: 1}\n\n";
        SseFrameReader reader = SseFrameReader.capturing(stream(first + second), GENEROUS);

        assertRaw(reader.nextRawFrame(), first, ": keep-alive\n\n");
        assertRaw(reader.nextRawFrame(), second, second);
        assertThat(reader.nextRawFrame()).isNull();
    }

    @Test
    void keepsCarriageReturnLineFeedTerminatorsIncludingTheFinalLineFeed() throws IOException {
        String first = "id: 1\r\ndata: one\r\n\r\n";
        String second = "event: message\r\ndata: {\"x\":\r\ndata: 2}\r\n\r\n";
        SseFrameReader reader = SseFrameReader.capturing(stream(first + second), GENEROUS);

        assertRaw(reader.nextRawFrame(), first, "id: 1\ndata: one\n\n");
        assertRaw(reader.nextRawFrame(), second, "event: message\ndata: {\"x\":\ndata: 2}\n\n");
        assertThat(reader.nextRawFrame()).isNull();
    }

    @Test
    void keepsCarriageReturnOnlyTerminators() throws IOException {
        SseFrameReader reader = SseFrameReader.capturing(stream("data: a\r\rdata: b\r\r"), GENEROUS);

        assertRaw(reader.nextRawFrame(), "data: a\r\r", "data: a\n\n");
        assertRaw(reader.nextRawFrame(), "data: b\r\r", "data: b\n\n");
    }

    @Test
    void aLineFeedArrivingAfterTheFrameIsNotCountedInTheNextFrame() throws IOException {
        SseFrameReader reader = SseFrameReader.capturing(new NothingAvailable(stream("data: a\r\n\r\ndata: b\r\n\r\n")),
                GENEROUS);

        assertRaw(reader.nextRawFrame(), "data: a\r\n\r", "data: a\n\n");
        assertRaw(reader.nextRawFrame(), "data: b\r\n\r", "data: b\n\n");
    }

    @Test
    void aCapturingReaderOverARemainderStillTakesTheFinalLineFeedThatHasArrived() throws IOException {
        InputStream wire = stream("event: endpoint\r\ndata: /m\r\n\r\ndata: a\r\n\r\n");
        SseFrameReader endpoint = SseFrameReader.over(wire, GENEROUS);
        endpoint.nextFrame();

        SseFrameReader events = SseFrameReader.capturing(endpoint.remainder(wire), GENEROUS);

        assertRaw(events.nextRawFrame(), "data: a\r\n\r\n", "data: a\n\n");
    }

    @Test
    void keepsBytesThatAreNotValidUtf8() throws IOException {
        byte[] wire = {'d', 'a', 't', 'a', ':', ' ', (byte) 0xff, (byte) 0xfe, '\n', '\n'};
        SseFrameReader reader = SseFrameReader.capturing(new ByteArrayInputStream(wire), GENEROUS);

        assertThat(reader.nextRawFrame().bytes()).isEqualTo(wire);
    }

    @Test
    void readsTheSameFramesAsTheUncapturingReader() throws IOException {
        String wire = "data: 1\r\n\r\n\n: c\n\ndata: 2\r\r";
        SseFrameReader plain = SseFrameReader.over(stream(wire), GENEROUS);
        SseFrameReader capturing = SseFrameReader.capturing(stream(wire), GENEROUS);

        for (String frame = plain.nextFrame(); frame != null; frame = plain.nextFrame()) {
            assertThat(capturing.nextRawFrame().text()).isEqualTo(frame);
        }
        assertThat(capturing.nextRawFrame()).isNull();
    }

    private static void assertRaw(RawSseFrame frame, String bytes, String text) {
        assertThat(new String(frame.bytes(), StandardCharsets.UTF_8)).isEqualTo(bytes);
        assertThat(frame.text()).isEqualTo(text);
    }

    private static InputStream stream(String text) {
        return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
    }

    private static final class NothingAvailable extends java.io.FilterInputStream {

        private NothingAvailable(InputStream in) {
            super(in);
        }

        @Override
        public int available() {
            return 0;
        }
    }
}
