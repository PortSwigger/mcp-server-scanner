package com.mcpscanner.proxy;

import com.mcpscanner.mcp.BoundedBodyReader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

final class BoundedPostBodySubscriber implements HttpResponse.BodySubscriber<String> {
    private final HttpResponse.BodySubscriber<String> delegate =
            HttpResponse.BodySubscribers.ofString(StandardCharsets.UTF_8);
    private final ByteArrayOutputStream received = new ByteArrayOutputStream();
    private Flow.Subscription subscription;
    private int receivedBytes;
    private boolean finished;

    @Override
    public CompletionStage<String> getBody() {
        return delegate.getBody();
    }

    @Override
    public void onSubscribe(Flow.Subscription subscription) {
        this.subscription = subscription;
        delegate.onSubscribe(subscription);
    }

    @Override
    public void onNext(List<ByteBuffer> chunks) {
        if (finished) return;
        for (ByteBuffer chunk : chunks) {
            if (chunk.remaining() > BoundedBodyReader.MAX_RESPONSE_BYTES - receivedBytes) {
                finished = true;
                subscription.cancel();
                delegate.onError(new IOException("Upstream response exceeded "
                        + BoundedBodyReader.MAX_RESPONSE_BYTES + " bytes"));
                return;
            }
            receivedBytes += chunk.remaining();
        }
        chunks.forEach(this::keep);
        delegate.onNext(chunks);
    }

    synchronized byte[] received() {
        return received.toByteArray();
    }

    private synchronized void keep(ByteBuffer chunk) {
        ByteBuffer copy = chunk.duplicate();
        byte[] bytes = new byte[copy.remaining()];
        copy.get(bytes);
        received.write(bytes, 0, bytes.length);
    }

    @Override
    public void onError(Throwable error) {
        if (finished) return;
        finished = true;
        delegate.onError(error);
    }

    @Override
    public void onComplete() {
        if (finished) return;
        finished = true;
        delegate.onComplete();
    }
}
