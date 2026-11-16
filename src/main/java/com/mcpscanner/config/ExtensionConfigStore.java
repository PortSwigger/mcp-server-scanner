package com.mcpscanner.config;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.core.oauth.RegistrationMode;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

public final class ExtensionConfigStore {

    public static final int DEFAULT_OAUTH_REDIRECT_PORT = 0;

    private static final String KEY_ENDPOINT = "mcp.endpoint";
    private static final String KEY_TRANSPORT = "mcp.transport";
    private static final String KEY_AUTH_TYPE = "mcp.auth.type";
    private static final String KEY_OAUTH_GRANT = "mcp.auth.oauth.grant";
    private static final String KEY_OAUTH_GRANT_MIGRATED = "mcp.auth.oauth.grant.migrated";
    private static final String KEY_REDIRECT_MODE = "mcp.redirect.mode";
    private static final String KEY_SEND_TO_HANDLE_AUTH = "mcp.sendto.handle_auth";
    private static final String KEY_ANSWER_SERVER_PINGS = "mcp.server_pings.answer";
    private static final String KEY_USE_BURP_NETWORKING = "mcp.networking.use_burp";
    private static final String KEY_AUTH_AUTO_DETECT = "mcp.auth.auto_detect";
    private static final String KEY_AUTH_AUTO_DETECT_MIGRATED = "mcp.auth.auto_detect.migrated";
    private static final String KEY_OAUTH_ISSUER = "mcp.oauth.issuer";
    private static final String KEY_OAUTH_REDIRECT_PORT = "mcp.oauth.redirect_port";
    private static final String KEY_OAUTH_SKIP_DCR = "mcp.oauth.skip_dcr";
    private static final String KEY_OAUTH_REGISTRATION_MODE = "mcp.oauth.registration_mode";
    private static final String KEY_OAUTH_CLIENT_ISSUER = "mcp.oauth.client_issuer";
    private static final String KEY_OAUTH_METADATA_URL = "mcp.oauth.client_metadata_url";
    private static final String KEY_OAUTH_CLIENT_ID = "mcp.oauth.client_id";
    private static final String KEY_OAUTH_SCOPES = "mcp.oauth.scopes";
    private static final String KEY_IDENTITIES = "mcp.identities";
    private static final String KEY_PRIMARY_PROFILE = "mcp.identities.primary";
    private static final String KEY_UNREADABLE_IDENTITIES_BACKUP = "mcp.identities.unreadable_backup";
    private static final String KEY_CHECK_PREFIX = "mcp.check.";
    private static final String KEY_CHECK_ENABLED_SUFFIX = ".enabled";
    private static final String KEY_FAMILY_PREFIX = "mcp.family.";
    private static final String KEY_HEADER_FIELDS_ENABLED = "mcp.fields.headers.enabled";
    private static final String KEY_SCAN_MODE = "mcp.scan.mode";
    private static final String KEY_MINING_PASSES = "mcp.mining.passes";
    private static final String KEY_MINING_WRITE_TOOLS = "mcp.mining.write_tools";
    private static final String KEY_MINED_IN_WRITE_TOOLS = "mcp.mining.mined_in_write_tools";
    private static final String KEY_SCOPE_PREFIX = "mcp.scope.";
    private static final String KEY_SCOPE_TOOL_INFIX = ".tool.";
    private static final String KEY_SCOPE_SELECTED_SUFFIX = ".selected";
    private static final String KEY_SCOPE_DONT_ASK_SUFFIX = ".dontAskAgain";
    private static final String KEY_SCOPE_ACCESS_INFIX = ".access.";
    private static final String KEY_SCOPE_EXPECTATION_SUFFIX = ".expectation";
    private static final String KEY_DCR_PREFIX = "mcp.dcr.";
    private static final String KEY_DCR_REG_TOKEN_SUFFIX = ".reg_token";
    private static final String KEY_DCR_REG_URI_SUFFIX = ".reg_uri";

    private static final TypeReference<List<PersistedScope>> SCOPE_LIST_TYPE = new TypeReference<>() {};

    private final PersistedObject store;
    private final Logging logging;
    private final Map<String, String> dcrManagementTokens = new ConcurrentHashMap<>();
    private final List<Runnable> settingsChangeListeners = new CopyOnWriteArrayList<>();
    private final List<Runnable> endpointChangeListeners = new CopyOnWriteArrayList<>();

    public ExtensionConfigStore(PersistedObject store, Logging logging) {
        this.store = store;
        this.logging = logging;
        migrateRegistrationMode();
        deleteDcrManagementTokensSavedByOlderVersions();
    }

    public ClientIdentity clientIdentity() {
        return ClientIdentity.from(field -> store.getString(field.key()));
    }

    public void saveClientIdentity(ClientIdentity identity) {
        for (ClientIdentityField field : ClientIdentityField.values()) {
            store.setString(field.key(), identity.value(field));
        }
    }

    public String endpoint() {
        return store.getString(KEY_ENDPOINT);
    }

    public void setEndpoint(String endpoint) {
        boolean changed = !Objects.equals(endpoint(), endpoint);
        store.setString(KEY_ENDPOINT, endpoint);
        if (changed) {
            endpointChangeListeners.forEach(Runnable::run);
        }
    }

    public void addEndpointChangeListener(Runnable listener) {
        endpointChangeListeners.add(Objects.requireNonNull(listener));
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

    public String oauthGrant() {
        return store.getString(KEY_OAUTH_GRANT);
    }

    public void setOauthGrant(String grant) {
        store.setString(KEY_OAUTH_GRANT, grant);
    }

    public boolean oauthGrantMigrated() {
        return Boolean.TRUE.equals(store.getBoolean(KEY_OAUTH_GRANT_MIGRATED));
    }

    public void retireOauthGrant() {
        store.deleteString(KEY_OAUTH_GRANT);
        store.setBoolean(KEY_OAUTH_GRANT_MIGRATED, true);
    }

    public RedirectMode redirectMode() {
        String saved = store.getString(KEY_REDIRECT_MODE);
        if (saved == null) return RedirectMode.METHOD_PRESERVING_SAME_ORIGIN;
        try {
            return RedirectMode.valueOf(saved);
        } catch (IllegalArgumentException invalid) {
            logging.logToError("Unknown saved redirect mode; using Same origin, 307/308 only");
            return RedirectMode.METHOD_PRESERVING_SAME_ORIGIN;
        }
    }

    public void setRedirectMode(RedirectMode mode) {
        store.setString(KEY_REDIRECT_MODE, Objects.requireNonNull(mode).name());
        notifySettingsChanged();
    }

    public long resourceCap(ResourceCap cap) {
        Long saved = store.getLong(cap.key());
        return saved != null && cap.accepts(saved) ? saved : cap.defaultValue();
    }

    public int extensionScanWorkers() {
        return Math.toIntExact(resourceCap(ResourceCap.EXTENSION_SCAN_WORKERS));
    }

    public void setResourceCap(ResourceCap cap, Long value) {
        if (value == null) {
            store.deleteLong(cap.key());
        } else if (cap.accepts(value)) {
            store.setLong(cap.key(), value);
        } else {
            throw new IllegalArgumentException(cap.label() + " must be between " + cap.minValue() + " and " + cap.maxValue());
        }
        notifySettingsChanged();
    }

    public boolean handleSendToAuthentication() {
        return Boolean.TRUE.equals(store.getBoolean(KEY_SEND_TO_HANDLE_AUTH));
    }

    public void setHandleSendToAuthentication(boolean handle) {
        store.setBoolean(KEY_SEND_TO_HANDLE_AUTH, handle);
        notifySettingsChanged();
    }

    public boolean answerServerPings() {
        return !Boolean.FALSE.equals(store.getBoolean(KEY_ANSWER_SERVER_PINGS));
    }

    public void setAnswerServerPings(boolean answer) {
        store.setBoolean(KEY_ANSWER_SERVER_PINGS, answer);
        notifySettingsChanged();
    }

    public boolean legacyAutoDetectAuth() {
        return !Boolean.FALSE.equals(store.getBoolean(KEY_AUTH_AUTO_DETECT));
    }

    public boolean autoDetectMigrated() {
        return Boolean.TRUE.equals(store.getBoolean(KEY_AUTH_AUTO_DETECT_MIGRATED));
    }

    public void markAutoDetectMigrated() {
        store.setBoolean(KEY_AUTH_AUTO_DETECT_MIGRATED, true);
    }

    public boolean useBurpNetworking() {
        return !Boolean.FALSE.equals(store.getBoolean(KEY_USE_BURP_NETWORKING));
    }

    public void setUseBurpNetworking(boolean use) {
        store.setBoolean(KEY_USE_BURP_NETWORKING, use);
        notifySettingsChanged();
    }

    public void addSettingsChangeListener(Runnable listener) {
        settingsChangeListeners.add(Objects.requireNonNull(listener));
    }

    private void notifySettingsChanged() {
        settingsChangeListeners.forEach(Runnable::run);
    }

    public String oauthIssuer() {
        return store.getString(KEY_OAUTH_ISSUER);
    }

    public void setOauthIssuer(String issuer) {
        store.setString(KEY_OAUTH_ISSUER, issuer);
    }

    public int oauthRedirectPort() {
        Integer port = store.getInteger(KEY_OAUTH_REDIRECT_PORT);
        return port != null ? port : DEFAULT_OAUTH_REDIRECT_PORT;
    }

    public void setOauthRedirectPort(int port) {
        store.setInteger(KEY_OAUTH_REDIRECT_PORT, port);
    }

    public boolean oauthSkipDcr() {
        Boolean skip = store.getBoolean(KEY_OAUTH_SKIP_DCR);
        return skip != null && skip;
    }

    public RegistrationMode oauthRegistrationMode() {
        String saved = store.getString(KEY_OAUTH_REGISTRATION_MODE);
        return saved == null ? legacyRegistrationMode() : parseRegistrationMode(saved).orElse(RegistrationMode.AUTO);
    }

    private void migrateRegistrationMode() {
        String saved = store.getString(KEY_OAUTH_REGISTRATION_MODE);
        if (saved == null) {
            migrateLegacyRegistrationChoice();
        } else if (parseRegistrationMode(saved).isEmpty()) {
            logging.logToError("Unknown saved OAuth registration mode; using Auto");
            setOauthRegistrationMode(RegistrationMode.AUTO);
        }
    }

    private void migrateLegacyRegistrationChoice() {
        if (legacyRegistrationMode() != RegistrationMode.PRE_REGISTERED) {
            return;
        }
        if (oauthIssuer() != null) {
            setOauthClientIssuer(oauthIssuer());
        }
        setOauthRegistrationMode(RegistrationMode.PRE_REGISTERED);
    }

    private RegistrationMode legacyRegistrationMode() {
        return oauthSkipDcr() ? RegistrationMode.PRE_REGISTERED : RegistrationMode.AUTO;
    }

    private static Optional<RegistrationMode> parseRegistrationMode(String saved) {
        try {
            return Optional.of(RegistrationMode.valueOf(saved));
        } catch (IllegalArgumentException unknown) {
            return Optional.empty();
        }
    }

    public void setOauthRegistrationMode(RegistrationMode mode) {
        store.setString(KEY_OAUTH_REGISTRATION_MODE, mode.name());
    }

    public String oauthClientIssuer() {
        return store.getString(KEY_OAUTH_CLIENT_ISSUER);
    }

    public void setOauthClientIssuer(String issuer) {
        store.setString(KEY_OAUTH_CLIENT_ISSUER, issuer);
    }

    public String oauthClientMetadataUrl() {
        return store.getString(KEY_OAUTH_METADATA_URL);
    }

    public void setOauthClientMetadataUrl(String url) {
        store.setString(KEY_OAUTH_METADATA_URL, url);
    }

    public String oauthClientId() {
        return store.getString(KEY_OAUTH_CLIENT_ID);
    }

    public void setOauthClientId(String clientId) {
        store.setString(KEY_OAUTH_CLIENT_ID, clientId);
    }

    public String dcrRegistrationManagementToken(String issuer) {
        return dcrManagementTokens.get(dcrRegTokenKey(issuer).canonical());
    }

    public void setDcrRegistrationManagementToken(String issuer, String value) {
        dcrManagementTokens.put(dcrRegTokenKey(issuer).canonical(), value);
    }

    private void deleteDcrManagementTokensSavedByOlderVersions() {
        store.stringKeys().stream().filter(ExtensionConfigStore::isDcrRegTokenKey).toList()
                .forEach(store::deleteString);
    }

    private static boolean isDcrRegTokenKey(String key) {
        return key.startsWith(KEY_DCR_PREFIX) && key.endsWith(KEY_DCR_REG_TOKEN_SUFFIX);
    }

    public String dcrRegistrationClientUri(String issuer) {
        return readString(dcrRegUriKey(issuer));
    }

    public void setDcrRegistrationClientUri(String issuer, String uri) {
        store.setString(dcrRegUriKey(issuer).canonical(), uri);
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

    public String identitiesJson() {
        return store.getString(KEY_IDENTITIES);
    }

    public void setIdentitiesJson(String json) {
        store.setString(KEY_IDENTITIES, json);
    }

    public String primaryProfileJson() {
        return store.getString(KEY_PRIMARY_PROFILE);
    }

    public void clearPrimaryProfileJson() {
        store.deleteString(KEY_PRIMARY_PROFILE);
    }

    public String unreadableIdentitiesBackupJson() {
        return store.getString(KEY_UNREADABLE_IDENTITIES_BACKUP);
    }

    public void setUnreadableIdentitiesBackupJson(String json) {
        store.setString(KEY_UNREADABLE_IDENTITIES_BACKUP, json);
    }

    public Boolean checkEnabled(String id) {
        return store.getBoolean(KEY_CHECK_PREFIX + id + KEY_CHECK_ENABLED_SUFFIX);
    }

    public void setCheckEnabled(String id, boolean enabled) {
        store.setBoolean(KEY_CHECK_PREFIX + id + KEY_CHECK_ENABLED_SUFFIX, enabled);
    }

    public Boolean requestFamilyEnabled(String familyId) {
        return store.getBoolean(KEY_FAMILY_PREFIX + familyId + KEY_CHECK_ENABLED_SUFFIX);
    }

    public void setRequestFamilyEnabled(String familyId, boolean enabled) {
        store.setBoolean(KEY_FAMILY_PREFIX + familyId + KEY_CHECK_ENABLED_SUFFIX, enabled);
    }

    public Boolean headerFieldsEnabled() {
        return store.getBoolean(KEY_HEADER_FIELDS_ENABLED);
    }

    public void setHeaderFieldsEnabled(boolean enabled) {
        store.setBoolean(KEY_HEADER_FIELDS_ENABLED, enabled);
    }

    public String scanMode() {
        return store.getString(KEY_SCAN_MODE);
    }

    public void setScanMode(String mode) {
        store.setString(KEY_SCAN_MODE, mode);
    }

    public String miningPasses() {
        return store.getString(KEY_MINING_PASSES);
    }

    public void setMiningPasses(String passes) {
        store.setString(KEY_MINING_PASSES, passes);
    }

    public String miningWriteTools() {
        return store.getString(KEY_MINING_WRITE_TOOLS);
    }

    public void setMiningWriteTools(String writeTools) {
        store.setString(KEY_MINING_WRITE_TOOLS, writeTools);
    }

    public boolean minedIdsInWriteTools() {
        return Boolean.TRUE.equals(store.getBoolean(KEY_MINED_IN_WRITE_TOOLS));
    }

    public void setMinedIdsInWriteTools(boolean use) {
        store.setBoolean(KEY_MINED_IN_WRITE_TOOLS, use);
    }

    public Boolean toolSelected(String endpoint, String toolName) {
        return readBoolean(toolSelectedKey(endpoint, toolName));
    }

    public void setToolSelected(String endpoint, String toolName, boolean value) {
        store.setBoolean(toolSelectedKey(endpoint, toolName).canonical(), value);
    }

    public boolean dontAskAgain(String endpoint) {
        Boolean value = readBoolean(dontAskAgainKey(endpoint));
        return value != null && value;
    }

    public void setDontAskAgain(String endpoint, boolean value) {
        store.setBoolean(dontAskAgainKey(endpoint).canonical(), value);
    }

    public String accessExpectation(String endpoint, String item) {
        return readString(accessExpectationKey(endpoint, item));
    }

    public void setAccessExpectation(String endpoint, String item, String expectation) {
        store.setString(accessExpectationKey(endpoint, item).canonical(), expectation);
    }

    public int clearDontAskAgainForAllServers() {
        List<String> keys = store.booleanKeys().stream().filter(ExtensionConfigStore::isDontAskAgainKey).toList();
        keys.forEach(store::deleteBoolean);
        return keys.size();
    }

    private static boolean isDontAskAgainKey(String key) {
        return key.startsWith(KEY_SCOPE_PREFIX) && key.endsWith(KEY_SCOPE_DONT_ASK_SUFFIX);
    }

    private static HashedKey dcrRegTokenKey(String issuer) {
        return HashedKey.of(KEY_DCR_PREFIX, issuer, KEY_DCR_REG_TOKEN_SUFFIX);
    }

    private static HashedKey dcrRegUriKey(String issuer) {
        return HashedKey.of(KEY_DCR_PREFIX, issuer, KEY_DCR_REG_URI_SUFFIX);
    }

    private static HashedKey toolSelectedKey(String endpoint, String toolName) {
        return HashedKey.of(KEY_SCOPE_PREFIX, endpointOrEmpty(endpoint),
                KEY_SCOPE_TOOL_INFIX + toolName + KEY_SCOPE_SELECTED_SUFFIX);
    }

    private static HashedKey accessExpectationKey(String endpoint, String item) {
        return HashedKey.of(KEY_SCOPE_PREFIX, endpointOrEmpty(endpoint),
                KEY_SCOPE_ACCESS_INFIX + item + KEY_SCOPE_EXPECTATION_SUFFIX);
    }

    private static HashedKey dontAskAgainKey(String endpoint) {
        return HashedKey.of(KEY_SCOPE_PREFIX, endpointOrEmpty(endpoint), KEY_SCOPE_DONT_ASK_SUFFIX);
    }

    private static String endpointOrEmpty(String endpoint) {
        return Objects.requireNonNullElse(endpoint, "");
    }

    private String readString(HashedKey key) {
        return firstStored(key, store::getString);
    }

    private Boolean readBoolean(HashedKey key) {
        return firstStored(key, store::getBoolean);
    }

    private static <T> T firstStored(HashedKey key, Function<String, T> reader) {
        for (String candidate : key.lookupOrder()) {
            T value = reader.apply(candidate);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    public record PersistedScope(String name, boolean enabled, String source) {}
}
