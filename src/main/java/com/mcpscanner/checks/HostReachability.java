package com.mcpscanner.checks;

import java.util.Locale;

public final class HostReachability {

    private HostReachability() {}

    public static boolean isLocallyReachable(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String lower = host.toLowerCase(Locale.ROOT);
        if (lower.equals("localhost") || lower.endsWith(".localhost")) return true;
        if (lower.equals("127.0.0.1") || lower.startsWith("127.")) return true;
        if (lower.equals("::1")) return true;
        if (lower.startsWith("10.")) return true;
        if (lower.startsWith("192.168.")) return true;
        if (lower.startsWith("169.254.")) return true;
        if (lower.startsWith("172.") && secondOctetWithin(lower, 4, 16, 31)) return true;
        if (lower.startsWith("100.") && secondOctetWithin(lower, 4, 64, 127)) return true;
        if (isIpv6UniqueLocalAddress(lower)) return true;
        return false;
    }

    private static boolean secondOctetWithin(String host, int fromIndex, int min, int max) {
        int dot = host.indexOf('.', fromIndex);
        if (dot <= fromIndex) return false;
        try {
            int second = Integer.parseInt(host.substring(fromIndex, dot));
            return second >= min && second <= max;
        } catch (NumberFormatException ignored) {
            return false;
        }
    }

    private static boolean isIpv6UniqueLocalAddress(String host) {
        // RFC 4193: fc00::/7 — first byte is 0xfc or 0xfd, so the IPv6 literal's
        // first hextet starts with "fc" or "fd". Require an IPv6 colon to avoid
        // matching hostnames like "fc.example.com".
        if (host.indexOf(':') < 0 || host.length() < 3) return false;
        if (host.charAt(0) != 'f') return false;
        char second = host.charAt(1);
        if (second != 'c' && second != 'd') return false;
        char third = host.charAt(2);
        return third == ':' || isHexDigit(third);
    }

    private static boolean isHexDigit(char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    }
}
