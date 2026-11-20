package com.mcpscanner.proxy;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class PinnedBases {

    static final int MAX_BASES = 256;
    static final long MAX_BYTES = 4L * 1024 * 1024;

    private final int maxBases;
    private final long maxBytes;
    private final Map<String, Long> leastRecentlyUsedFirst = new LinkedHashMap<>(16, 0.75f, true);
    private long bytes;

    PinnedBases() {
        this(MAX_BASES, MAX_BYTES);
    }

    PinnedBases(int maxBases, long maxBytes) {
        this.maxBases = maxBases;
        this.maxBytes = maxBytes;
    }

    boolean isPinned(String id) {
        return leastRecentlyUsedFirst.get(id) != null;
    }

    void markUsed(String id) {
        leastRecentlyUsedFirst.get(id);
    }

    List<String> pin(String id, long size) {
        if (leastRecentlyUsedFirst.get(id) == null) {
            leastRecentlyUsedFirst.put(id, size);
            bytes += size;
        }
        return unpinOverBound(id);
    }

    private List<String> unpinOverBound(String newest) {
        List<String> unpinned = new ArrayList<>();
        Iterator<Map.Entry<String, Long>> oldestFirst = leastRecentlyUsedFirst.entrySet().iterator();
        while (overBound() && oldestFirst.hasNext()) {
            Map.Entry<String, Long> oldest = oldestFirst.next();
            if (!oldest.getKey().equals(newest)) {
                bytes -= oldest.getValue();
                unpinned.add(oldest.getKey());
                oldestFirst.remove();
            }
        }
        return unpinned;
    }

    private boolean overBound() {
        return leastRecentlyUsedFirst.size() > maxBases || bytes > maxBytes;
    }
}
