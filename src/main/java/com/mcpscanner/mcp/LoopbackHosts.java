package com.mcpscanner.mcp;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class LoopbackHosts {

    private static final Set<String> NAMED = Set.of("localhost", "127.0.0.1", "::1");
    private static final Pattern IPV4_LOOPBACK = Pattern.compile("127(\\.\\d{1,3}){3}");

    private LoopbackHosts() {
    }

    public static boolean isNamedLoopback(String host) {
        return host != null && NAMED.contains(withoutBrackets(host).toLowerCase(Locale.ROOT));
    }

    public static boolean isLoopback(String host) {
        return host != null && (isNamedLoopback(host) || isLoopbackLiteral(withoutBrackets(host)));
    }

    private static boolean isLoopbackLiteral(String host) {
        return IPV4_LOOPBACK.matcher(host).matches() || host.contains(":") && isIpv6Loopback(host);
    }

    private static boolean isIpv6Loopback(String literal) {
        try {
            return InetAddress.getByName(literal).isLoopbackAddress();
        } catch (UnknownHostException malformed) {
            return false;
        }
    }

    private static String withoutBrackets(String host) {
        return host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
    }
}
