package com.mcpscanner.config;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.mcp.McpObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

public final class ExtensionConfigStore {

    private static final String KEY_ENDPOINT = "mcp.endpoint";
    private static final String KEY_TRANSPORT = "mcp.transport";
    private static final String KEY_AUTH_TYPE = "mcp.auth.type";
    private static final String KEY_OAUTH_ISSUER = "mcp.oauth.issuer";
    private static final String KEY_OAUTH_REDIRECT_PORT = "mcp.oauth.redirect_port";
    private static final String KEY_OAUTH_SKIP_DCR = "mcp.oauth.skip_dcr";
    private static final String KEY_OAUTH_CLIENT_ID = "mcp.oauth.client_id";
    private static final String KEY_OAUTH_SCOPES = "mcp.oauth.scopes";
    private static final String KEY_CHECK_PREFIX = "mcp.check.";
    private static final String KEY_CHECK_ENABLED_SUFFIX = ".enabled";
    private static final String KEY_SCOPE_PREFIX = "mcp.scope.";
    private static final String KEY_SCOPE_TOOL_INFIX = ".tool.";
    private static final String KEY_SCOPE_SELECTED_SUFFIX = ".selected";
    private static final String KEY_SCOPE_DONT_ASK_SUFFIX = ".dontAskAgain";
    private static final String KEY_DCR_PREFIX = "mcp.dcr.";
    private static final String KEY_DCR_REG_TOKEN_SUFFIX = ".reg_token";
    private static final String KEY_DCR_REG_URI_SUFFIX = ".reg_uri";
    private static final int ENDPOINT_HASH_LENGTH = 16;

    private static final TypeReference<List<PersistedScope>> SCOPE_LIST_TYPE = new TypeReference<>() {};

    private final PersistedObject store;
    private final Logging logging;

    public ExtensionConfigStore(PersistedObject store, Logging logging) {
        this.store = store;
        this.logging = logging;
    }

    public String endpoint() {
        return store.getString(KEY_ENDPOINT);
    }

    public void setEndpoint(String endpoint) {
        store.setString(KEY_ENDPOINT, endpoint);
    }

    public String transport() {
        return store.getString(KEY_TRANSPORT);
    }

    public void setTransport(String transport) {
        store.setString(KEY_TRANSPORT, transport);
    }

    public String authType() {
        return store.getString(KEY_AUTH_TYPE);
    }

    public void setAuthType(String authType) {
        store.setString(KEY_AUTH_TYPE, authType);
    }

    public String oauthIssuer() {
        return store.getString(KEY_OAUTH_ISSUER);
    }

    public void setOauthIssuer(String issuer) {
        store.setString(KEY_OAUTH_ISSUER, issuer);
    }

    public int oauthRedirectPort() {
        Integer port = store.getInteger(KEY_OAUTH_REDIRECT_PORT);
        return port != null ? port : OAuthClientHints.DEFAULT_REDIRECT_PORT;
    }

    public void setOauthRedirectPort(int port) {
        store.setInteger(KEY_OAUTH_REDIRECT_PORT, port);
    }

    public boolean oauthSkipDcr() {
        Boolean skip = store.getBoolean(KEY_OAUTH_SKIP_DCR);
        return skip != null && skip;
    }

    public void setOauthSkipDcr(boolean skip) {
        store.setBoolean(KEY_OAUTH_SKIP_DCR, skip);
    }

    public String oauthClientId() {
        return store.getString(KEY_OAUTH_CLIENT_ID);
    }

    public void setOauthClientId(String clientId) {
        store.setString(KEY_OAUTH_CLIENT_ID, clientId);
    }

    public String dcrRegistrationManagementToken(String issuer) {
        return store.getString(dcrRegTokenKey(issuer));
    }

    public void setDcrRegistrationManagementToken(String issuer, String value) {
        store.setString(dcrRegTokenKey(issuer), value);
    }

    public String dcrRegistrationClientUri(String issuer) {
        return store.getString(dcrRegUriKey(issuer));
    }

    public void setDcrRegistrationClientUri(String issuer, String uri) {
        store.setString(dcrRegUriKey(issuer), uri);
    }

    public List<PersistedScope> scopes() {
        String json = store.getString(KEY_OAUTH_SCOPES);
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return McpObjectMapper.INSTANCE.readValue(json, SCOPE_LIST_TYPE);
        } catch (JsonProcessingException e) {
            logging.logToError("Corrupt persisted scope list: " + e.getMessage());
            return List.of();
        }
    }

    public void setScopes(List<PersistedScope> scopes) {
        try {
            store.setString(KEY_OAUTH_SCOPES, McpObjectMapper.INSTANCE.writeValueAsString(scopes));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize scopes", e);
        }
    }

    public Boolean checkEnabled(String id) {
        return store.getBoolean(KEY_CHECK_PREFIX + id + KEY_CHECK_ENABLED_SUFFIX);
    }

    public void setCheckEnabled(String id, boolean enabled) {
        store.setBoolean(KEY_CHECK_PREFIX + id + KEY_CHECK_ENABLED_SUFFIX, enabled);
    }

    public Boolean toolSelected(String endpoint, String toolName) {
        return store.getBoolean(toolSelectedKey(endpoint, toolName));
    }

    public void setToolSelected(String endpoint, String toolName, boolean value) {
        store.setBoolean(toolSelectedKey(endpoint, toolName), value);
    }

    public boolean dontAskAgain(String endpoint) {
        Boolean value = store.getBoolean(dontAskAgainKey(endpoint));
        return value != null && value;
    }

    public void setDontAskAgain(String endpoint, boolean value) {
        store.setBoolean(dontAskAgainKey(endpoint), value);
    }

    private static String dcrRegTokenKey(String issuer) {
        return KEY_DCR_PREFIX + issuerHash(issuer) + KEY_DCR_REG_TOKEN_SUFFIX;
    }

    private static String dcrRegUriKey(String issuer) {
        return KEY_DCR_PREFIX + issuerHash(issuer) + KEY_DCR_REG_URI_SUFFIX;
    }

    private static String issuerHash(String issuer) {
        if (issuer == null) {
            return "null";
        }
        String normalised = issuer.trim().toLowerCase();
        while (normalised.endsWith("/")) {
            normalised = normalised.substring(0, normalised.length() - 1);
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(normalised.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, ENDPOINT_HASH_LENGTH);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String toolSelectedKey(String endpoint, String toolName) {
        return KEY_SCOPE_PREFIX + endpointHash(endpoint) + KEY_SCOPE_TOOL_INFIX
                + toolName + KEY_SCOPE_SELECTED_SUFFIX;
    }

    private static String dontAskAgainKey(String endpoint) {
        return KEY_SCOPE_PREFIX + endpointHash(endpoint) + KEY_SCOPE_DONT_ASK_SUFFIX;
    }

    private static String endpointHash(String endpoint) {
        String normalised = normaliseEndpoint(endpoint);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(normalised.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, ENDPOINT_HASH_LENGTH);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String normaliseEndpoint(String endpoint) {
        if (endpoint == null) {
            return "";
        }
        String trimmed = endpoint.trim().toLowerCase();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    public record PersistedScope(String name, boolean enabled, String source) {}
}
