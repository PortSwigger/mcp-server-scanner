package com.mcpscanner.signedin;

import burp.api.montoya.http.message.Cookie;

import java.time.ZonedDateTime;
import java.util.Optional;

record JarCookie(String name, String value, String domain, String path, Optional<ZonedDateTime> expiration)
        implements Cookie {

    static JarCookie session(String domain, String path, String name, String value) {
        return new JarCookie(name, value, domain, path, Optional.empty());
    }

    static JarCookie expiringAt(ZonedDateTime expiration, String domain, String name, String value) {
        return new JarCookie(name, value, domain, "/", Optional.of(expiration));
    }
}
