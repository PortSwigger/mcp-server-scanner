package com.mcpscanner.logging;

import com.mcpscanner.logging.McpEventLog.LogEntry;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;

public final class RetainedLogEntries {

    public record Eviction(LogEntry entry, int position) {}

    private enum Retention { DISPOSABLE, ROUTINE, KEPT }

    private final int capacity;
    private final int keptCapacity;
    private final List<LogEntry> entries;
    private final Map<Retention, Integer> counts = new EnumMap<>(Retention.class);

    public RetainedLogEntries(int capacity) {
        this.capacity = capacity;
        this.keptCapacity = capacity / 2;
        this.entries = new ArrayList<>(capacity);
        resetCounts();
    }

    public Optional<Eviction> add(LogEntry entry) {
        Optional<Eviction> eviction = entries.size() == capacity ? evict(victim()) : Optional.empty();
        entries.add(entry);
        counts.merge(retentionOf(entry), 1, Integer::sum);
        return eviction;
    }

    public List<LogEntry> snapshot() {
        return List.copyOf(entries);
    }

    public void clear() {
        entries.clear();
        resetCounts();
    }

    private void resetCounts() {
        for (Retention retention : Retention.values()) {
            counts.put(retention, 0);
        }
    }

    private Retention victim() {
        if (counts.get(Retention.DISPOSABLE) > 0) {
            return Retention.DISPOSABLE;
        }
        if (counts.get(Retention.KEPT) > keptCapacity || counts.get(Retention.ROUTINE) == 0) {
            return Retention.KEPT;
        }
        return Retention.ROUTINE;
    }

    private Optional<Eviction> evict(Retention victim) {
        return IntStream.range(0, entries.size())
                .filter(position -> retentionOf(entries.get(position)) == victim)
                .boxed()
                .findFirst()
                .map(position -> {
                    counts.merge(victim, -1, Integer::sum);
                    return new Eviction(entries.remove(position.intValue()), position);
                });
    }

    private static Retention retentionOf(LogEntry entry) {
        if (entry.level() == McpEventLog.Level.DEBUG) {
            return Retention.DISPOSABLE;
        }
        return entry.kept() ? Retention.KEPT : Retention.ROUTINE;
    }
}
