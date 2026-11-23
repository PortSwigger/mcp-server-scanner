package com.mcpscanner.automation;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.http.BareRequests;
import com.mcpscanner.http.EmptyResponse;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.LongSupplier;

public final class SendCanary {

    private final Http http;
    private final Function<Duration, Http> queuedBehindScanQueue;
    private final LongSupplier nanoClock;

    public SendCanary(Http http, Function<Duration, Http> queuedBehindScanQueue) {
        this(http, queuedBehindScanQueue, System::nanoTime);
    }

    SendCanary(Http http, LongSupplier nanoClock) {
        this(http, wait -> http, nanoClock);
    }

    SendCanary(Http http, Function<Duration, Http> queuedBehindScanQueue, LongSupplier nanoClock) {
        this.http = http;
        this.queuedBehindScanQueue = queuedBehindScanQueue;
        this.nanoClock = nanoClock;
    }

    public SendCanaryReport run(SendCanaryCommand command) {
        HttpRequest request = BareRequests.fromUrl(command.url());
        Http sender = senderFor(command);
        ExecutorService senders = Executors.newFixedThreadPool(command.concurrency(), SendCanary::daemon);
        try {
            long started = nanoClock.getAsLong();
            List<Future<TimedSend>> sends = senders.invokeAll(Collections.nCopies(command.count(), () -> timed(sender, request)));
            List<TimedSend> timed = completed(sends);
            return new SendCanaryReport(timed.stream().map(TimedSend::micros).toList(),
                    micros(nanoClock.getAsLong() - started),
                    (int) timed.stream().filter(send -> !send.answered()).count());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while sending the canary", interrupted);
        } finally {
            senders.shutdownNow();
        }
    }

    private Http senderFor(SendCanaryCommand command) {
        return command.queued() ? queuedBehindScanQueue.apply(command.queueWait()) : http;
    }

    private TimedSend timed(Http sender, HttpRequest request) {
        long started = nanoClock.getAsLong();
        boolean answered = answered(sender, request);
        return new TimedSend(micros(nanoClock.getAsLong() - started), answered);
    }

    private static boolean answered(Http sender, HttpRequest request) {
        try {
            HttpRequestResponse exchange = sender.sendRequest(request);
            return exchange != null && exchange.response() != null && !EmptyResponse.is(exchange.response());
        } catch (RuntimeException failed) {
            return false;
        }
    }

    private static List<TimedSend> completed(List<Future<TimedSend>> sends) throws InterruptedException {
        List<TimedSend> timed = new ArrayList<>(sends.size());
        for (Future<TimedSend> send : sends) {
            try {
                timed.add(send.get());
            } catch (ExecutionException impossible) {
                throw new IllegalStateException(impossible.getCause());
            }
        }
        return timed;
    }

    private static long micros(long nanos) {
        return TimeUnit.NANOSECONDS.toMicros(nanos);
    }

    private static Thread daemon(Runnable runnable) {
        Thread thread = new Thread(runnable, "mcp-send-canary");
        thread.setDaemon(true);
        return thread;
    }

    private record TimedSend(long micros, boolean answered) {
    }
}
