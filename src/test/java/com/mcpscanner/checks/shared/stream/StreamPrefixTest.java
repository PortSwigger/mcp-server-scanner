package com.mcpscanner.checks.shared.stream;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Flow;

import static org.assertj.core.api.Assertions.assertThat;

class StreamPrefixTest {

    private static final Duration WINDOW = Duration.ofMillis(50);

    @Test
    void aPrefixFillingExactlyTheCapIsNotFlaggedAsCut() throws InterruptedException {
        StreamPrefix prefix = subscribed(4);

        prefix.onNext(List.of(buffer("abcd")));

        StreamPrefix.Read read = prefix.await(WINDOW);
        assertThat(new String(read.bytes(), StandardCharsets.UTF_8)).isEqualTo("abcd");
        assertThat(read.capped()).isFalse();
    }

    @Test
    void aPrefixWithBytesBeyondTheCapIsFlaggedAsCut() throws InterruptedException {
        StreamPrefix prefix = subscribed(4);

        prefix.onNext(List.of(buffer("ab"), buffer("cde")));

        StreamPrefix.Read read = prefix.await(WINDOW);
        assertThat(new String(read.bytes(), StandardCharsets.UTF_8)).isEqualTo("abcd");
        assertThat(read.capped()).isTrue();
    }

    @Test
    void aShortStreamThatEndsIsNeitherCutNorOpen() throws InterruptedException {
        StreamPrefix prefix = subscribed(4);

        prefix.onNext(List.of(buffer("ab")));
        prefix.onComplete();

        StreamPrefix.Read read = prefix.await(WINDOW);
        assertThat(read.ended()).isTrue();
        assertThat(read.capped()).isFalse();
    }

    private static StreamPrefix subscribed(int maxBytes) {
        StreamPrefix prefix = new StreamPrefix(maxBytes);
        prefix.onSubscribe(new IdleSubscription());
        return prefix;
    }

    private static ByteBuffer buffer(String text) {
        return ByteBuffer.wrap(text.getBytes(StandardCharsets.UTF_8));
    }

    private static final class IdleSubscription implements Flow.Subscription {
        @Override
        public void request(long n) {
        }

        @Override
        public void cancel() {
        }
    }
}
