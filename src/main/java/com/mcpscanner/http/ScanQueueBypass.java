package com.mcpscanner.http;

import burp.api.montoya.http.Http;

import java.util.Objects;
import java.util.Optional;

public final class ScanQueueBypass {

    public static final ScanQueueBypass NONE = new ScanQueueBypass(Optional.empty());

    private final Optional<Http> unqueued;

    private ScanQueueBypass(Optional<Http> unqueued) {
        this.unqueued = unqueued;
    }

    public static ScanQueueBypass through(Http unqueued) {
        return new ScanQueueBypass(Optional.of(Objects.requireNonNull(unqueued)));
    }

    public static Http alreadyOffScanQueue(Http http) {
        return http instanceof OffScanQueueHttp ? http : new OffScanQueueHttp(http);
    }

    public Http around(Http scan) {
        if (scan instanceof OffScanQueueHttp) {
            return scan;
        }
        return unqueued.<Http>map(outside -> new ScanQueueBypassingHttp(scan, outside)).orElse(scan);
    }
}
