package com.mcpscanner.mcp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.Set;

public final class LaunchedBases {

    static final int MAX_BODIES = 4_096;

    private final int maxBodies;
    private final Set<String> unsent = new LinkedHashSet<>();

    public LaunchedBases() {
        this(MAX_BODIES);
    }

    LaunchedBases(int maxBodies) {
        this.maxBodies = maxBodies;
    }

    public synchronized void remember(String body) {
        String digest = digestOf(body);
        unsent.remove(digest);
        unsent.add(digest);
        if (unsent.size() > maxBodies) {
            unsent.remove(unsent.iterator().next());
        }
    }

    public synchronized boolean claimFirstSend(String body) {
        return body != null && unsent.remove(digestOf(body));
    }

    private static String digestOf(String body) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(body.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException missing) {
            throw new IllegalStateException("SHA-256 is required of every JDK", missing);
        }
    }
}
