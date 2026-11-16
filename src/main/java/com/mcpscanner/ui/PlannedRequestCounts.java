package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.UiReads;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

final class PlannedRequestCounts<T> {

    static final int CAPACITY = 16;

    private final UiReads reads;
    private final Map<Object, T> known = new RecentlyUsed<>();
    private final Set<Object> counting = new HashSet<>();
    private Runnable onCounted = () -> { };
    private long generation;

    PlannedRequestCounts(UiReads reads) {
        this.reads = reads;
    }

    void onCounted(Runnable listener) {
        onCounted = listener;
    }

    Optional<T> count(Object key, Supplier<T> plan) {
        if (!known.containsKey(key) && counting.add(key)) {
            long startedIn = generation;
            reads.compute(plan, count -> counted(key, count, startedIn));
        }
        return Optional.ofNullable(known.get(key));
    }

    void invalidate() {
        generation++;
        known.clear();
        counting.clear();
    }

    private void counted(Object key, T count, long startedIn) {
        if (startedIn != generation) {
            return;
        }
        counting.remove(key);
        known.put(key, count);
        onCounted.run();
    }

    private static final class RecentlyUsed<T> extends LinkedHashMap<Object, T> {
        RecentlyUsed() {
            super(CAPACITY, 0.75f, true);
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<Object, T> eldest) {
            return size() > CAPACITY;
        }
    }
}
