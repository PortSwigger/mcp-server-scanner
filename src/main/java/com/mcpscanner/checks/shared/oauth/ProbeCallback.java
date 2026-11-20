package com.mcpscanner.checks.shared.oauth;

import java.net.URI;
import java.util.Optional;

public final class ProbeCallback {

    private static final String LOOPBACK_HOST = "127.0.0.1";
    private static final String IPV6_LOOPBACK_HOST = "[::1]";
    private static final int LOOPBACK_PORT = 49151;

    private ProbeCallback() {
    }

    public static URI loopback(String path) {
        return loopback(LOOPBACK_HOST, path);
    }

    public static URI loopback(String host, String path) {
        return URI.create("http://" + host + ":" + LOOPBACK_PORT + "/" + path);
    }

    public static String hostUnrelatedTo(Optional<URI> scannerRedirect) {
        return scannerRedirect.map(URI::getHost).filter(host -> !LOOPBACK_HOST.equals(host)).isPresent()
                ? LOOPBACK_HOST : IPV6_LOOPBACK_HOST;
    }

    public static boolean matches(URI callback, URI location) {
        return location.isAbsolute() && location.getRawUserInfo() == null && location.getHost() != null
                && callback.getScheme().equalsIgnoreCase(location.getScheme())
                && callback.getHost().equalsIgnoreCase(location.getHost())
                && callback.getPort() == location.getPort()
                && callback.getRawPath().equals(location.getRawPath());
    }

    public static Optional<CallbackResponse> response(URI callback, URI location, String state) {
        if (!matches(callback, location) || !keepsRegisteredQuery(callback, location)) {
            return Optional.empty();
        }
        String raw = location.getRawFragment() != null ? location.getRawFragment() : location.getRawQuery();
        return raw == null ? Optional.empty() : singleOutcome(new OAuthResponseParameters(raw), state);
    }

    private static boolean keepsRegisteredQuery(URI callback, URI location) {
        String registeredQuery = callback.getRawQuery();
        String actualQuery = location.getRawQuery();
        if (registeredQuery != null && (actualQuery == null
                || !(actualQuery.equals(registeredQuery) || actualQuery.startsWith(registeredQuery + "&")))) {
            return false;
        }
        return location.getRawFragment() == null || actualQuery == null || actualQuery.equals(registeredQuery);
    }

    private static Optional<CallbackResponse> singleOutcome(OAuthResponseParameters parameters, String state) {
        boolean stateMatches = parameters.count("state") == 1
                && parameters.single("state").filter(state::equals).isPresent();
        if (!stateMatches || parameters.count("code") > 1 || parameters.count("error") > 1) {
            return Optional.empty();
        }
        Optional<String> code = parameters.single("code");
        boolean error = parameters.single("error").isPresent();
        return code.isPresent() == error ? Optional.empty() : Optional.of(new CallbackResponse(code));
    }
}
