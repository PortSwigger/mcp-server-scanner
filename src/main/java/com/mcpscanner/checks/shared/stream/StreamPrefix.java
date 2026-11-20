package com.mcpscanner.checks.shared.stream;

import java.io.ByteArrayOutputStream;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

final class StreamPrefix implements HttpResponse.BodySubscriber<StreamPrefix> {

    record Read(byte[] bytes, boolean ended, boolean capped) {
    }

    private final int maxBytes;
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    private final CompletableFuture<Boolean> ended = new CompletableFuture<>();
    private final CompletableFuture<Flow.Subscription> subscription = new CompletableFuture<>();
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private boolean cut;

    StreamPrefix(int maxBytes) {
        this.maxBytes = maxBytes;
    }

    @Override
    public CompletionStage<StreamPrefix> getBody() {
        return CompletableFuture.completedStage(this);
    }

    @Override
    public void onSubscribe(Flow.Subscription upstream) {
        subscription.complete(upstream);
        if (cancelled.get()) {
            upstream.cancel();
        } else {
            upstream.request(1);
        }
    }

    @Override
    public void onNext(List<ByteBuffer> buffers) {
        if (cancelled.get()) {
            return;
        }
        if (append(buffers)) {
            ended.complete(false);
            cancel();
        } else {
            subscription.join().request(1);
        }
    }

    @Override
    public void onError(Throwable failure) {
        ended.complete(true);
    }

    @Override
    public void onComplete() {
        ended.complete(true);
    }

    Read await(Duration window) throws InterruptedException {
        try {
            boolean serverEnded = endedWithin(window);
            return new Read(snapshot(), serverEnded, wasCut());
        } finally {
            cancel();
        }
    }

    private boolean endedWithin(Duration window) throws InterruptedException {
        try {
            return ended.get(window.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException stillOpen) {
            return false;
        } catch (ExecutionException impossible) {
            return true;
        }
    }

    private synchronized boolean append(List<ByteBuffer> buffers) {
        for (ByteBuffer buffer : buffers) {
            int take = Math.min(buffer.remaining(), maxBytes - bytes.size());
            byte[] chunk = new byte[take];
            buffer.get(chunk);
            bytes.write(chunk, 0, take);
            cut |= buffer.hasRemaining();
        }
        return bytes.size() >= maxBytes;
    }

    private synchronized boolean wasCut() {
        return cut;
    }

    private synchronized byte[] snapshot() {
        return bytes.toByteArray();
    }

    void cancel() {
        if (cancelled.compareAndSet(false, true)) {
            subscription.thenAccept(Flow.Subscription::cancel);
        }
    }
}
