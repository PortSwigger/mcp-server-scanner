package com.mcpscanner.config;

import java.util.Arrays;
import java.util.Comparator;
import java.util.Optional;
import java.util.Set;

import static com.mcpscanner.config.SettingScope.PROJECT_ONLY;
import static com.mcpscanner.config.SettingScope.USER_DEFAULT;

public enum SettingKey {
    ENDPOINT("mcp.endpoint", PROJECT_ONLY),
    TRANSPORT("mcp.transport", PROJECT_ONLY),
    AUTH_TYPE("mcp.auth.type", PROJECT_ONLY),
    OAUTH_GRANT("mcp.auth.oauth.grant", PROJECT_ONLY),
    OAUTH_GRANT_MIGRATED("mcp.auth.oauth.grant.migrated", PROJECT_ONLY),
    AUTH_AUTO_DETECT("mcp.auth.auto_detect", PROJECT_ONLY),
    AUTH_AUTO_DETECT_MIGRATED("mcp.auth.auto_detect.migrated", PROJECT_ONLY),
    OAUTH_ISSUER("mcp.oauth.issuer", PROJECT_ONLY),
    OAUTH_SKIP_DCR("mcp.oauth.skip_dcr", PROJECT_ONLY),
    OAUTH_CLIENT_ISSUER("mcp.oauth.client_issuer", PROJECT_ONLY),
    OAUTH_METADATA_URL("mcp.oauth.client_metadata_url", PROJECT_ONLY),
    OAUTH_CLIENT_ID("mcp.oauth.client_id", PROJECT_ONLY),
    OAUTH_SCOPES("mcp.oauth.scopes", PROJECT_ONLY),
    IDENTITIES("mcp.identities", PROJECT_ONLY),
    PRIMARY_PROFILE("mcp.identities.primary", PROJECT_ONLY),
    UNREADABLE_IDENTITIES_BACKUP("mcp.identities.unreadable_backup", PROJECT_ONLY),
    MINING_WRITE_TOOLS("mcp.mining.write_tools", PROJECT_ONLY),
    MINED_IN_WRITE_TOOLS("mcp.mining.mined_in_write_tools", PROJECT_ONLY),
    SERVER_SCOPED("mcp.scope.", "", PROJECT_ONLY),
    DCR_REGISTRATION("mcp.dcr.", "", PROJECT_ONLY),
    CLIENT_VERSION("mcp.client.version", PROJECT_ONLY),
    OAUTH_CONSENT_SIGNED_IN("mcp.oauth.consent.signed_in", PROJECT_ONLY),
    OAUTH_REGISTRATION_MODE("mcp.oauth.registration_mode", PROJECT_ONLY),
    SEEDED_FROM_USER_DEFAULTS("mcp.defaults.seeded", PROJECT_ONLY),

    OAUTH_REDIRECT_PORT("mcp.oauth.redirect_port", USER_DEFAULT),
    REDIRECT_MODE("mcp.redirect.mode", USER_DEFAULT, RedirectMode.ALWAYS.name()),
    SEND_TO_HANDLE_AUTH("mcp.sendto.handle_auth", USER_DEFAULT),
    ANSWER_SERVER_PINGS("mcp.server_pings.answer", USER_DEFAULT),
    USE_BURP_NETWORKING("mcp.networking.use_burp", USER_DEFAULT),
    SCAN_MODE("mcp.scan.mode", USER_DEFAULT),
    HEADER_FIELDS_ENABLED("mcp.fields.headers.enabled", USER_DEFAULT),
    META_ENVELOPE_EVERY_REQUEST("mcp.fields.meta.every_request", USER_DEFAULT),
    CHECK_ENABLED("mcp.check.", ".enabled", USER_DEFAULT),
    REQUEST_FAMILY_ENABLED("mcp.family.", ".enabled", USER_DEFAULT),
    MINING_PASSES("mcp.mining.passes", USER_DEFAULT),
    CLIENT_IDENTITY("mcp.client.", "", USER_DEFAULT),
    CAP_PROXY_POST_BODY("mcp.proxy.post_body_limit_bytes", USER_DEFAULT),
    CAP_SSE_PENDING_RESPONSE("mcp.cap.sse_pending_response_bytes", USER_DEFAULT),
    CAP_DISCOVERY_TOTAL("mcp.cap.discovery_total_bytes", USER_DEFAULT),
    CAP_DISCOVERY_MAX_PAGES("mcp.cap.discovery_max_pages", USER_DEFAULT),
    CAP_MINING_REQUESTS_PER_USER("mcp.mining.requests_per_user", USER_DEFAULT),
    CAP_EXTENSION_SCAN_WORKERS("mcp.scan.engine_workers", USER_DEFAULT);

    private final String prefix;
    private final String suffix;
    private final boolean family;
    private final SettingScope scope;
    private final Set<String> riskyValues;

    SettingKey(String key, SettingScope scope, String... riskyValues) {
        this(key, "", false, scope, Set.of(riskyValues));
    }

    SettingKey(String prefix, String suffix, SettingScope scope) {
        this(prefix, suffix, true, scope, Set.of());
    }

    SettingKey(String prefix, String suffix, boolean family, SettingScope scope, Set<String> riskyValues) {
        this.prefix = prefix;
        this.suffix = suffix;
        this.family = family;
        this.scope = scope;
        this.riskyValues = riskyValues;
    }

    public static Optional<SettingKey> declaring(String key) {
        return Arrays.stream(values()).filter(declared -> declared.matches(key))
                .min(Comparator.comparing(declared -> declared.family));
    }

    public static boolean allowsUserDefault(String key) {
        return declaring(key).map(declared -> declared.scope == USER_DEFAULT).orElse(false);
    }

    public static boolean allowsUserDefault(String key, Object value) {
        return declaring(key)
                .map(declared -> declared.scope == USER_DEFAULT && !declared.riskyValues.contains(String.valueOf(value)))
                .orElse(false);
    }

    public SettingScope scope() {
        return scope;
    }

    public String key() {
        if (family) {
            throw new IllegalStateException(name() + " names a family of keys");
        }
        return prefix;
    }

    public String key(String member) {
        if (!family) {
            throw new IllegalStateException(name() + " names a single key");
        }
        return prefix + member + suffix;
    }

    public String prefix() {
        return prefix;
    }

    private boolean matches(String key) {
        return family ? isMember(key) : key.equals(prefix);
    }

    private boolean isMember(String key) {
        return key.startsWith(prefix) && key.endsWith(suffix) && key.length() > prefix.length() + suffix.length();
    }
}
