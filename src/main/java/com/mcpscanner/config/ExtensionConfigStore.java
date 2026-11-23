package com.mcpscanner.config;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Preferences;
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

    private static final String KEY_SCOPE_TOOL_INFIX = ".tool.";
    private static final String KEY_SCOPE_SELECTED_SUFFIX = ".selected";
    private static final String KEY_SCOPE_DONT_ASK_SUFFIX = ".dontAskAgain";
    private static final String KEY_SCOPE_ACCESS_INFIX = ".access.";
    private static final String KEY_SCOPE_EXPECTATION_SUFFIX = ".expectation";
    private static final String KEY_DCR_REG_TOKEN_SUFFIX = ".reg_token";
    private static final String KEY_DCR_REG_URI_SUFFIX = ".reg_uri";

    private static final TypeReference<List<PersistedScope>> SCOPE_LIST_TYPE = new TypeReference<>() {};

    private final LayeredSettings store;
    private final Logging logging;
    private final Map<String, String> dcrManagementTokens = new ConcurrentHashMap<>();
    private final List<Runnable> settingsChangeListeners = new CopyOnWriteArrayList<>();
    private final List<Runnable> endpointChangeListeners = new CopyOnWriteArrayList<>();

    public ExtensionConfigStore(PersistedObject project, Preferences userDefaults, Logging logging) {
        this.store = new LayeredSettings(project, userDefaults);
        this.logging = logging;
        store.startNewProjectFromUserDefaults();
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
        return store.getString(SettingKey.ENDPOINT.key());
    }

    public void setEndpoint(String endpoint) {
        boolean changed = !Objects.equals(endpoint(), endpoint);
        store.setString(SettingKey.ENDPOINT.key(), endpoint);
        if (changed) {
            endpointChangeListeners.forEach(Runnable::run);
        }
    }

    public void addEndpointChangeListener(Runnable listener) {
        endpointChangeListeners.add(Objects.requireNonNull(listener));
    }

    public String transport() {
        return store.getString(SettingKey.TRANSPORT.key());
    }

    public void setTransport(String transport) {
        store.setString(SettingKey.TRANSPORT.key(), transport);
    }

    public String authType() {
        return store.getString(SettingKey.AUTH_TYPE.key());
    }

    public void setAuthType(String authType) {
        store.setString(SettingKey.AUTH_TYPE.key(), authType);
    }

    public String oauthGrant() {
        return store.getString(SettingKey.OAUTH_GRANT.key());
    }

    public void setOauthGrant(String grant) {
        store.setString(SettingKey.OAUTH_GRANT.key(), grant);
    }

    public boolean oauthGrantMigrated() {
        return Boolean.TRUE.equals(store.getBoolean(SettingKey.OAUTH_GRANT_MIGRATED.key()));
    }

    public void retireOauthGrant() {
        store.deleteString(SettingKey.OAUTH_GRANT.key());
        store.setBoolean(SettingKey.OAUTH_GRANT_MIGRATED.key(), true);
    }

    public RedirectMode redirectMode() {
        String saved = store.getString(SettingKey.REDIRECT_MODE.key());
        if (saved == null) return RedirectMode.METHOD_PRESERVING_SAME_ORIGIN;
        try {
            return RedirectMode.valueOf(saved);
        } catch (IllegalArgumentException invalid) {
            logging.logToError("Unknown saved redirect mode; using Same origin, 307/308 only");
            return RedirectMode.METHOD_PRESERVING_SAME_ORIGIN;
        }
    }

    public void setRedirectMode(RedirectMode mode) {
        store.setString(SettingKey.REDIRECT_MODE.key(), Objects.requireNonNull(mode).name());
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
        return Boolean.TRUE.equals(store.getBoolean(SettingKey.SEND_TO_HANDLE_AUTH.key()));
    }

    public void setHandleSendToAuthentication(boolean handle) {
        store.setBoolean(SettingKey.SEND_TO_HANDLE_AUTH.key(), handle);
        notifySettingsChanged();
    }

    public boolean answerServerPings() {
        return !Boolean.FALSE.equals(store.getBoolean(SettingKey.ANSWER_SERVER_PINGS.key()));
    }

    public void setAnswerServerPings(boolean answer) {
        store.setBoolean(SettingKey.ANSWER_SERVER_PINGS.key(), answer);
        notifySettingsChanged();
    }

    public boolean legacyAutoDetectAuth() {
        return !Boolean.FALSE.equals(store.getBoolean(SettingKey.AUTH_AUTO_DETECT.key()));
    }

    public boolean autoDetectMigrated() {
        return Boolean.TRUE.equals(store.getBoolean(SettingKey.AUTH_AUTO_DETECT_MIGRATED.key()));
    }

    public void markAutoDetectMigrated() {
        store.setBoolean(SettingKey.AUTH_AUTO_DETECT_MIGRATED.key(), true);
    }

    public boolean useBurpNetworking() {
        return !Boolean.FALSE.equals(store.getBoolean(SettingKey.USE_BURP_NETWORKING.key()));
    }

    public void setUseBurpNetworking(boolean use) {
        store.setBoolean(SettingKey.USE_BURP_NETWORKING.key(), use);
        notifySettingsChanged();
    }

    public void saveAsUserDefaults() {
        store.saveProjectValuesAsUserDefaults();
    }

    public void resetUserDefaults() {
        store.clearUserDefaults();
    }

    public void addSettingsChangeListener(Runnable listener) {
        settingsChangeListeners.add(Objects.requireNonNull(listener));
    }

    private void notifySettingsChanged() {
        settingsChangeListeners.forEach(Runnable::run);
    }

    public String oauthIssuer() {
        return store.getString(SettingKey.OAUTH_ISSUER.key());
    }

    public void setOauthIssuer(String issuer) {
        store.setString(SettingKey.OAUTH_ISSUER.key(), issuer);
    }

    public int oauthRedirectPort() {
        Integer port = store.getInteger(SettingKey.OAUTH_REDIRECT_PORT.key());
        return port != null ? port : DEFAULT_OAUTH_REDIRECT_PORT;
    }

    public void setOauthRedirectPort(int port) {
        store.setInteger(SettingKey.OAUTH_REDIRECT_PORT.key(), port);
    }

    public boolean oauthSkipDcr() {
        Boolean skip = store.getBoolean(SettingKey.OAUTH_SKIP_DCR.key());
        return skip != null && skip;
    }

    public RegistrationMode oauthRegistrationMode() {
        String saved = store.getString(SettingKey.OAUTH_REGISTRATION_MODE.key());
        return saved == null ? legacyRegistrationMode() : parseRegistrationMode(saved).orElse(RegistrationMode.AUTO);
    }

    private void migrateRegistrationMode() {
        String saved = store.getString(SettingKey.OAUTH_REGISTRATION_MODE.key());
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
        store.setString(SettingKey.OAUTH_REGISTRATION_MODE.key(), mode.name());
    }

    public String oauthClientIssuer() {
        return store.getString(SettingKey.OAUTH_CLIENT_ISSUER.key());
    }

    public void setOauthClientIssuer(String issuer) {
        store.setString(SettingKey.OAUTH_CLIENT_ISSUER.key(), issuer);
    }

    public String oauthClientMetadataUrl() {
        return store.getString(SettingKey.OAUTH_METADATA_URL.key());
    }

    public void setOauthClientMetadataUrl(String url) {
        store.setString(SettingKey.OAUTH_METADATA_URL.key(), url);
    }

    public String oauthClientId() {
        return store.getString(SettingKey.OAUTH_CLIENT_ID.key());
    }

    public void setOauthClientId(String clientId) {
        store.setString(SettingKey.OAUTH_CLIENT_ID.key(), clientId);
    }

    public String dcrRegistrationManagementToken(String issuer) {
        return dcrManagementTokens.get(dcrRegTokenKey(issuer).canonical());
    }

    public void setDcrRegistrationManagementToken(String issuer, String value) {
        dcrManagementTokens.put(dcrRegTokenKey(issuer).canonical(), value);
    }

    private void deleteDcrManagementTokensSavedByOlderVersions() {
        store.projectStringKeys().stream().filter(ExtensionConfigStore::isDcrRegTokenKey).toList()
                .forEach(store::deleteString);
    }

    private static boolean isDcrRegTokenKey(String key) {
        return key.startsWith(SettingKey.DCR_REGISTRATION.prefix()) && key.endsWith(KEY_DCR_REG_TOKEN_SUFFIX);
    }

    public String dcrRegistrationClientUri(String issuer) {
        return readString(dcrRegUriKey(issuer));
    }

    public void setDcrRegistrationClientUri(String issuer, String uri) {
        store.setString(dcrRegUriKey(issuer).canonical(), uri);
    }

    public List<PersistedScope> scopes() {
        String json = store.getString(SettingKey.OAUTH_SCOPES.key());
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
            store.setString(SettingKey.OAUTH_SCOPES.key(), McpObjectMapper.INSTANCE.writeValueAsString(scopes));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize scopes", e);
        }
    }

    public String identitiesJson() {
        return store.getString(SettingKey.IDENTITIES.key());
    }

    public void setIdentitiesJson(String json) {
        store.setString(SettingKey.IDENTITIES.key(), json);
    }

    public String primaryProfileJson() {
        return store.getString(SettingKey.PRIMARY_PROFILE.key());
    }

    public void clearPrimaryProfileJson() {
        store.deleteString(SettingKey.PRIMARY_PROFILE.key());
    }

    public String unreadableIdentitiesBackupJson() {
        return store.getString(SettingKey.UNREADABLE_IDENTITIES_BACKUP.key());
    }

    public void setUnreadableIdentitiesBackupJson(String json) {
        store.setString(SettingKey.UNREADABLE_IDENTITIES_BACKUP.key(), json);
    }

    public Boolean checkEnabled(String id) {
        return store.getBoolean(SettingKey.CHECK_ENABLED.key(id));
    }

    public void setCheckEnabled(String id, boolean enabled) {
        store.setBoolean(SettingKey.CHECK_ENABLED.key(id), enabled);
    }

    public Boolean requestFamilyEnabled(String familyId) {
        return store.getBoolean(SettingKey.REQUEST_FAMILY_ENABLED.key(familyId));
    }

    public void setRequestFamilyEnabled(String familyId, boolean enabled) {
        store.setBoolean(SettingKey.REQUEST_FAMILY_ENABLED.key(familyId), enabled);
    }

    public Boolean headerFieldsEnabled() {
        return store.getBoolean(SettingKey.HEADER_FIELDS_ENABLED.key());
    }

    public void setHeaderFieldsEnabled(boolean enabled) {
        store.setBoolean(SettingKey.HEADER_FIELDS_ENABLED.key(), enabled);
    }

    public Boolean metaEnvelopeFuzzedOnEveryRequest() {
        return store.getBoolean(SettingKey.META_ENVELOPE_EVERY_REQUEST.key());
    }

    public void setMetaEnvelopeFuzzedOnEveryRequest(boolean enabled) {
        store.setBoolean(SettingKey.META_ENVELOPE_EVERY_REQUEST.key(), enabled);
    }

    public String scanMode() {
        return store.getString(SettingKey.SCAN_MODE.key());
    }

    public void setScanMode(String mode) {
        store.setString(SettingKey.SCAN_MODE.key(), mode);
    }

    public String miningPasses() {
        return store.getString(SettingKey.MINING_PASSES.key());
    }

    public void setMiningPasses(String passes) {
        store.setString(SettingKey.MINING_PASSES.key(), passes);
    }

    public String miningWriteTools() {
        return store.getString(SettingKey.MINING_WRITE_TOOLS.key());
    }

    public void setMiningWriteTools(String writeTools) {
        store.setString(SettingKey.MINING_WRITE_TOOLS.key(), writeTools);
    }

    public boolean minedIdsInWriteTools() {
        return Boolean.TRUE.equals(store.getBoolean(SettingKey.MINED_IN_WRITE_TOOLS.key()));
    }

    public void setMinedIdsInWriteTools(boolean use) {
        store.setBoolean(SettingKey.MINED_IN_WRITE_TOOLS.key(), use);
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
        List<String> keys = store.projectBooleanKeys().stream().filter(ExtensionConfigStore::isDontAskAgainKey).toList();
        keys.forEach(store::deleteBoolean);
        return keys.size();
    }

    private static boolean isDontAskAgainKey(String key) {
        return key.startsWith(SettingKey.SERVER_SCOPED.prefix()) && key.endsWith(KEY_SCOPE_DONT_ASK_SUFFIX);
    }

    private static HashedKey dcrRegTokenKey(String issuer) {
        return HashedKey.of(SettingKey.DCR_REGISTRATION.prefix(), issuer, KEY_DCR_REG_TOKEN_SUFFIX);
    }

    public boolean signedInConsentOptedIn() {
        return Boolean.TRUE.equals(store.getBoolean(SettingKey.OAUTH_CONSENT_SIGNED_IN.key()));
    }

    public void setSignedInConsentOptedIn(boolean optedIn) {
        store.setBoolean(SettingKey.OAUTH_CONSENT_SIGNED_IN.key(), optedIn);
    }

    private static HashedKey dcrRegUriKey(String issuer) {
        return HashedKey.of(SettingKey.DCR_REGISTRATION.prefix(), issuer, KEY_DCR_REG_URI_SUFFIX);
    }

    private static HashedKey toolSelectedKey(String endpoint, String toolName) {
        return HashedKey.of(SettingKey.SERVER_SCOPED.prefix(), endpointOrEmpty(endpoint),
                KEY_SCOPE_TOOL_INFIX + toolName + KEY_SCOPE_SELECTED_SUFFIX);
    }

    private static HashedKey accessExpectationKey(String endpoint, String item) {
        return HashedKey.of(SettingKey.SERVER_SCOPED.prefix(), endpointOrEmpty(endpoint),
                KEY_SCOPE_ACCESS_INFIX + item + KEY_SCOPE_EXPECTATION_SUFFIX);
    }

    private static HashedKey dontAskAgainKey(String endpoint) {
        return HashedKey.of(SettingKey.SERVER_SCOPED.prefix(), endpointOrEmpty(endpoint), KEY_SCOPE_DONT_ASK_SUFFIX);
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
