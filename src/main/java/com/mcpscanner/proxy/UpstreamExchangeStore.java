package com.mcpscanner.proxy;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.http.ExchangeLease;
import com.mcpscanner.http.ExchangeRetention;
import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.ScannerSentinels;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public final class UpstreamExchangeStore implements UpstreamExchanges {

    static final int MAX_EXCHANGES = 4_096;
    static final long MAX_BODY_BYTES = 32L * 1024 * 1024;
    static final long MAX_RETAINED_BYTES = 8L * 1024 * 1024;
    static final int MAX_RETAINED_EXCHANGES = MAX_EXCHANGES / 2;
    private static final int ID_BYTES = 16;

    private final int maxExchanges;
    private final long maxBodyBytes;
    private final long maxRetainedBytes;
    private final int maxRetainedExchanges;
    private final McpEventLog eventLog;
    private final SecureRandom random = new SecureRandom();
    private final ExchangeEvidence evidence = new ExchangeEvidence();
    private final Map<String, RecordedExchange> exchanges = new LinkedHashMap<>();
    private final Map<String, Integer> holds = new HashMap<>();
    private final Map<String, Integer> retentionsHolding = new HashMap<>();
    private final Set<Retention> retentions = new LinkedHashSet<>();
    private long bodyBytes;
    private long retainedBytes;

    public UpstreamExchangeStore() {
        this(McpEventLog.noop());
    }

    public UpstreamExchangeStore(McpEventLog eventLog) {
        this(MAX_EXCHANGES, MAX_BODY_BYTES, MAX_RETAINED_BYTES, MAX_RETAINED_EXCHANGES, eventLog);
    }

    UpstreamExchangeStore(int maxExchanges, long maxBodyBytes) {
        this(maxExchanges, maxBodyBytes, MAX_RETAINED_BYTES);
    }

    UpstreamExchangeStore(int maxExchanges, long maxBodyBytes, long maxRetainedBytes) {
        this(maxExchanges, maxBodyBytes, maxRetainedBytes, MAX_RETAINED_EXCHANGES, McpEventLog.noop());
    }

    UpstreamExchangeStore(int maxExchanges, long maxBodyBytes, long maxRetainedBytes,
                          int maxRetainedExchanges, McpEventLog eventLog) {
        this.maxExchanges = maxExchanges;
        this.maxBodyBytes = maxBodyBytes;
        this.maxRetainedBytes = maxRetainedBytes;
        this.maxRetainedExchanges = maxRetainedExchanges;
        this.eventLog = eventLog;
    }

    synchronized int retainedExchanges() {
        return retentionsHolding.size();
    }

    synchronized long retainedBytes() {
        return retainedBytes;
    }

    synchronized int size() {
        return exchanges.size();
    }

    synchronized String put(RecordedExchange exchange) {
        String id = newId();
        exchanges.put(id, exchange);
        bodyBytes += exchange.bodyBytes();
        evictOverflow();
        return id;
    }

    @Override
    public Optional<HttpRequestResponse> upstreamOf(HttpRequestResponse proxied) {
        return exchangeIdOf(proxied).flatMap(this::find).map(evidence::of);
    }

    private static Optional<String> exchangeIdOf(HttpRequestResponse proxied) {
        HttpResponse response = proxied == null ? null : proxied.response();
        return response == null ? Optional.empty()
                : Optional.ofNullable(response.headerValue(ScannerSentinels.EXCHANGE_HEADER));
    }

    private synchronized Optional<RecordedExchange> find(String id) {
        return Optional.ofNullable(exchanges.get(id));
    }

    @Override
    public ExchangeLease retaining() {
        return new Lease();
    }

    private synchronized void hold(String id) {
        holds.merge(id, 1, Integer::sum);
    }

    private synchronized void release(List<String> ids) {
        ids.forEach(id -> holds.computeIfPresent(id, (key, count) -> count == 1 ? null : count - 1));
        evictOverflow();
    }

    private synchronized Retention retain(List<String> ids) {
        ids.forEach(this::hold);
        Retention retention = new Retention(ids, bytesOf(ids));
        retentions.add(retention);
        retainedBytes += retention.bytes;
        retention.ids.forEach(id -> retentionsHolding.merge(id, 1, Integer::sum));
        releaseOldestRetentionsOverBudget(retention);
        return retention;
    }

    private long bytesOf(List<String> ids) {
        return ids.stream().map(exchanges::get).filter(java.util.Objects::nonNull)
                .mapToLong(RecordedExchange::bodyBytes).sum();
    }

    private boolean overBudget() {
        return retainedBytes > maxRetainedBytes || retentionsHolding.size() > maxRetainedExchanges;
    }

    private void releaseOldestRetentionsOverBudget(Retention newest) {
        while (overBudget() && !retentions.isEmpty()) {
            Retention oldest = retentions.iterator().next();
            oldest.release();
            if (oldest == newest) {
                eventLog.warn("Retained exchanges of one invocation exceed the retention budget ("
                        + maxRetainedBytes + " bytes, " + maxRetainedExchanges
                        + " exchanges); released at once, so their evidence is no longer available");
            }
        }
    }

    private final class Retention implements ExchangeRetention {

        private final List<String> ids;
        private final long bytes;
        private boolean released;

        private Retention(List<String> ids, long bytes) {
            this.ids = ids;
            this.bytes = bytes;
        }

        @Override
        public void release() {
            synchronized (UpstreamExchangeStore.this) {
                if (!released) {
                    released = true;
                    retentions.remove(this);
                    retainedBytes -= bytes;
                    ids.forEach(id -> retentionsHolding.computeIfPresent(id, (key, count) -> count == 1 ? null : count - 1));
                    UpstreamExchangeStore.this.release(ids);
                }
            }
        }
    }

    private void evictOverflow() {
        Iterator<Map.Entry<String, RecordedExchange>> oldestFirst = exchanges.entrySet().iterator();
        while (oldestFirst.hasNext() && (exchanges.size() > maxExchanges || bodyBytes > maxBodyBytes)) {
            Map.Entry<String, RecordedExchange> oldest = oldestFirst.next();
            if (!holds.containsKey(oldest.getKey())) {
                bodyBytes -= oldest.getValue().bodyBytes();
                oldestFirst.remove();
            }
        }
    }

    private final class Lease implements ExchangeLease {

        private final List<String> held = new ArrayList<>();

        @Override
        public synchronized void hold(HttpRequestResponse proxied) {
            exchangeIdOf(proxied).filter(id -> find(id).isPresent()).ifPresent(id -> {
                UpstreamExchangeStore.this.hold(id);
                held.add(id);
            });
        }

        @Override
        public synchronized ExchangeRetention retainBeyondClose() {
            return retain(List.copyOf(held));
        }

        @Override
        public synchronized void close() {
            release(held);
            held.clear();
        }
    }

    private String newId() {
        byte[] id = new byte[ID_BYTES];
        random.nextBytes(id);
        return HexFormat.of().formatHex(id);
    }
}
