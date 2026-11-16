package com.mcpscanner.access.mining;

import com.mcpscanner.mcp.NameTokens;

import java.util.List;
import java.util.Set;

final class SecretName {

    private static final String BARE_KEY = "key";
    private static final String SIGNED = "signed";
    private static final String SIGNED_BY = "by";
    private static final Set<String> SECRET_PARTS = Set.of("token", "tokens", "secret", "secrets", "password",
            "passwords", "passwd", "auth", "authorization", "credential", "credentials", "session", "sessions",
            "cookie", "cookies", "bearer", "jwt", "presigned", "signature", "signatures");
    private static final Set<String> SECRET_KEY_ENDINGS = Set.of("apikey", "privatekey", "secretkey", "accesskey",
            "signingkey", "encryptionkey");

    private SecretName() {
    }

    static boolean matches(String name) {
        if (name == null) {
            return false;
        }
        List<String> parts = NameTokens.of(name);
        return BARE_KEY.equals(String.join("", parts)) || parts.stream().anyMatch(SECRET_PARTS::contains)
                || endsWithSecretKey(parts) || signedLink(parts);
    }

    private static boolean signedLink(List<String> parts) {
        for (int index = 0; index < parts.size(); index++) {
            boolean authorship = index + 1 < parts.size() && SIGNED_BY.equals(parts.get(index + 1));
            if (SIGNED.equals(parts.get(index)) && !authorship) {
                return true;
            }
        }
        return false;
    }

    private static boolean endsWithSecretKey(List<String> parts) {
        for (int start = 0; start < parts.size(); start++) {
            if (SECRET_KEY_ENDINGS.contains(String.join("", parts.subList(start, parts.size())))) {
                return true;
            }
        }
        return false;
    }
}
