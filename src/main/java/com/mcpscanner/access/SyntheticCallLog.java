package com.mcpscanner.access;

import com.mcpscanner.checks.api.AccessItemKey;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

public final class SyntheticCallLog implements Consumer<SyntheticCall> {

    private final Map<CallKey, SyntheticCall> calls = new ConcurrentHashMap<>();

    @Override
    public void accept(SyntheticCall call) {
        calls.put(new CallKey(call.item(), call.principal().id()), call);
    }

    public Optional<SyntheticCall> call(AccessItemKey item, String principalId) {
        return Optional.ofNullable(calls.get(new CallKey(item, principalId)));
    }

    public List<SyntheticCall> calls() {
        return List.copyOf(calls.values());
    }

    public void clear() {
        calls.clear();
    }

    private record CallKey(AccessItemKey item, String principalId) {
    }
}
