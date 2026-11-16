package com.mcpscanner.scan.field;

import com.mcpscanner.scan.ArgumentPath;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

public final class AddedArgumentRegistry {

    static final int REMEMBERED = 4096;

    private record Holding(ArgumentPath added, int holders) {

        Holding heldOnceMore(ArgumentPath path) {
            return new Holding(path, holders + 1);
        }
    }

    private final Map<String, Holding> holdingByBody = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Holding> eldest) {
                    return size() > REMEMBERED;
                }
            });

    public void record(String body, ArgumentPath added) {
        holdingByBody.merge(body, new Holding(added, 1), (held, fresh) -> held.heldOnceMore(added));
    }

    public Optional<ArgumentPath> addedTo(String body) {
        return Optional.ofNullable(holdingByBody.get(body)).map(Holding::added);
    }

    public boolean isProbe(String body) {
        return holdingByBody.containsKey(body);
    }

    public void release(String body) {
        holdingByBody.computeIfPresent(body, (key, held) -> held.holders() > 1
                ? new Holding(held.added(), held.holders() - 1) : null);
    }
}
