package com.mcpscanner.checks.catalog.outboundrequest;

import burp.api.montoya.http.message.HttpHeader;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

record ProbeUserInfo(Optional<String> userInfo) {

    private static final String BASIC_SCHEME = "basic ";
    private static final Pattern URL_USER_INFO = Pattern.compile("^[A-Za-z][A-Za-z0-9+.-]*://([^/?#]*)@");

    static ProbeUserInfo of(String probeValue) {
        Matcher url = URL_USER_INFO.matcher(probeValue.strip());
        return new ProbeUserInfo(Optional.of(url).filter(Matcher::find).map(found -> found.group(1)));
    }

    boolean supplied(HttpHeader header) {
        return userInfo.isPresent() && "authorization".equalsIgnoreCase(header.name())
                && basicCredentials(header.value()).filter(this::isProbeUserInfo).isPresent();
    }

    private boolean isProbeUserInfo(String credentials) {
        String probe = userInfo.orElseThrow();
        return Set.of(probe, probe + ":").contains(credentials);
    }

    private static Optional<String> basicCredentials(String value) {
        String trimmed = value.strip();
        if (!trimmed.regionMatches(true, 0, BASIC_SCHEME, 0, BASIC_SCHEME.length())) {
            return Optional.empty();
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(trimmed.substring(BASIC_SCHEME.length()).strip());
            return Optional.of(new String(decoded, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException notBase64) {
            return Optional.empty();
        }
    }
}
