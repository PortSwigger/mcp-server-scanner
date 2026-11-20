package com.mcpscanner.signedin;

import burp.api.montoya.http.message.Cookie;

@FunctionalInterface
public interface CookieOrigins {

    boolean setForWholeDomain(Cookie jarCookie);
}
