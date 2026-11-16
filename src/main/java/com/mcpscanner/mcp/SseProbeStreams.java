package com.mcpscanner.mcp;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

public interface SseProbeStreams {

    SseProbeStream open(Map<String, String> headers);

    default Optional<String> streamUrl() {
        return Optional.empty();
    }

    static SseProbeStreams at(String streamUrl, Function<Map<String, String>, SseProbeStream> opener) {
        return new SseProbeStreams() {
            @Override
            public SseProbeStream open(Map<String, String> headers) {
                return opener.apply(headers);
            }

            @Override
            public Optional<String> streamUrl() {
                return Optional.of(streamUrl);
            }
        };
    }
}
