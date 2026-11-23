package com.mcpscanner.scan.field;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class MetaEnvelopeRegistry {

    public enum Role { CARRIER, PASSENGER }

    static final int REMEMBERED = 16384;

    private record Holds(int carriers, int passengers) {

        static final Holds NONE = new Holds(0, 0);

        Holds plus(Role role, int delta) {
            return role == Role.CARRIER
                    ? new Holds(Math.max(0, carriers + delta), passengers)
                    : new Holds(carriers, Math.max(0, passengers + delta));
        }

        boolean isEmpty() {
            return carriers == 0 && passengers == 0;
        }

        boolean leavesEnvelopeAlone() {
            return carriers == 0 && passengers > 0;
        }
    }

    private final Map<String, Holds> holdsByBody = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Holds> eldest) {
                    return size() > REMEMBERED;
                }
            });

    public void hold(String body, Role role) {
        holdsByBody.merge(body, Holds.NONE.plus(role, 1), (held, fresh) -> held.plus(role, 1));
    }

    public void release(String body, Role role) {
        holdsByBody.computeIfPresent(body, (key, held) -> {
            Holds remaining = held.plus(role, -1);
            return remaining.isEmpty() ? null : remaining;
        });
    }

    public boolean fuzzesEnvelopeOf(String body) {
        Holds held = holdsByBody.get(body);
        return held == null || !held.leavesEnvelopeAlone();
    }
}
