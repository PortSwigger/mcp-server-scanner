package com.mcpscanner.proxy;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class PendingResponseBuffer {
    private final LinkedHashMap<String, StreamedReply> responses = new LinkedHashMap<>();
    private long totalBytes;

    List<String> put(String id, StreamedReply response, long budgetBytes) {
        StreamedReply replaced = responses.put(id, response);
        if (replaced != null) {
            totalBytes -= sizeOf(replaced);
        }
        totalBytes += sizeOf(response);
        return evictOldestBeyond(budgetBytes);
    }

    StreamedReply remove(String id) {
        StreamedReply removed = responses.remove(id);
        if (removed != null) {
            totalBytes -= sizeOf(removed);
        }
        return removed;
    }

    int size() {
        return responses.size();
    }

    long totalBytes() {
        return totalBytes;
    }

    void clear() {
        responses.clear();
        totalBytes = 0;
    }

    private List<String> evictOldestBeyond(long budgetBytes) {
        List<String> evicted = new ArrayList<>();
        Iterator<Map.Entry<String, StreamedReply>> oldestFirst = responses.entrySet().iterator();
        while (totalBytes > budgetBytes && oldestFirst.hasNext()) {
            Map.Entry<String, StreamedReply> oldest = oldestFirst.next();
            totalBytes -= sizeOf(oldest.getValue());
            oldestFirst.remove();
            evicted.add(oldest.getKey());
        }
        return evicted;
    }

    private static long sizeOf(StreamedReply response) {
        return response.size();
    }
}
