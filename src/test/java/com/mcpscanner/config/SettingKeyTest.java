package com.mcpscanner.config;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SettingKeyTest {

    private static final Set<SettingKey> PROJECT_ONLY = EnumSet.of(
            SettingKey.ENDPOINT, SettingKey.TRANSPORT, SettingKey.AUTH_TYPE, SettingKey.OAUTH_GRANT,
            SettingKey.OAUTH_GRANT_MIGRATED, SettingKey.AUTH_AUTO_DETECT, SettingKey.AUTH_AUTO_DETECT_MIGRATED,
            SettingKey.OAUTH_ISSUER, SettingKey.OAUTH_SKIP_DCR, SettingKey.OAUTH_CLIENT_ISSUER,
            SettingKey.OAUTH_METADATA_URL, SettingKey.OAUTH_CLIENT_ID, SettingKey.OAUTH_SCOPES,
            SettingKey.IDENTITIES, SettingKey.PRIMARY_PROFILE, SettingKey.UNREADABLE_IDENTITIES_BACKUP,
            SettingKey.MINING_WRITE_TOOLS, SettingKey.MINED_IN_WRITE_TOOLS, SettingKey.SERVER_SCOPED,
            SettingKey.DCR_REGISTRATION, SettingKey.CLIENT_VERSION, SettingKey.OAUTH_CONSENT_SIGNED_IN,
            SettingKey.OAUTH_REGISTRATION_MODE, SettingKey.SEEDED_FROM_USER_DEFAULTS);

    @Test
    void projectOnlyKeysAreExactlyTheTargetUserAndRiskyOptInSettings() {
        Set<SettingKey> declaredProjectOnly = EnumSet.noneOf(SettingKey.class);
        Arrays.stream(SettingKey.values()).filter(key -> key.scope() == SettingScope.PROJECT_ONLY)
                .forEach(declaredProjectOnly::add);

        assertThat(declaredProjectOnly).isEqualTo(PROJECT_ONLY);
    }

    @ParameterizedTest
    @ValueSource(strings = {"mcp.endpoint", "mcp.transport", "mcp.auth.type", "mcp.oauth.issuer",
            "mcp.oauth.client_id", "mcp.oauth.client_issuer", "mcp.oauth.client_metadata_url", "mcp.oauth.scopes",
            "mcp.identities", "mcp.identities.primary", "mcp.mining.write_tools",
            "mcp.mining.mined_in_write_tools", "mcp.scope.abc.tool.t.selected", "mcp.scope.abc.dontAskAgain",
            "mcp.scope.abc.access.tool:t.expectation", "mcp.dcr.abc.reg_uri", "mcp.dcr.abc.reg_token",
            "mcp.oauth.consent.signed_in", "mcp.oauth.registration_mode", "mcp.defaults.seeded"})
    void targetUserAndOptInKeysNeverTakeAUserDefault(String key) {
        assertThat(SettingKey.declaring(key)).isPresent();
        assertThat(SettingKey.allowsUserDefault(key)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"mcp.oauth.redirect_port", "mcp.redirect.mode",
            "mcp.sendto.handle_auth", "mcp.server_pings.answer", "mcp.networking.use_burp", "mcp.scan.mode",
            "mcp.fields.headers.enabled", "mcp.fields.meta.every_request", "mcp.check.ssrf.enabled",
            "mcp.family.batch.enabled", "mcp.mining.passes", "mcp.client.name", "mcp.client.oauth.client_name",
            "mcp.proxy.post_body_limit_bytes", "mcp.cap.sse_pending_response_bytes",
            "mcp.cap.discovery_total_bytes", "mcp.cap.discovery_max_pages", "mcp.mining.requests_per_user",
            "mcp.scan.engine_workers"})
    void howTheTesterWorksMayTakeAUserDefault(String key) {
        assertThat(SettingKey.allowsUserDefault(key)).isTrue();
    }

    @Test
    void everyResourceCapAndClientIdentityFieldMayTakeAUserDefault() {
        Arrays.stream(ResourceCap.values()).map(ResourceCap::key)
                .forEach(key -> assertThat(SettingKey.allowsUserDefault(key)).as(key).isTrue());
        Arrays.stream(ClientIdentityField.values()).filter(field -> field != ClientIdentityField.VERSION)
                .map(ClientIdentityField::key)
                .forEach(key -> assertThat(SettingKey.allowsUserDefault(key)).as(key).isTrue());
    }

    @Test
    void theClientVersionStaysInTheProjectSoAnUpgradeIsNotPinnedToAnOldVersion() {
        assertThat(SettingKey.declaring(ClientIdentityField.VERSION.key())).contains(SettingKey.CLIENT_VERSION);
        assertThat(SettingKey.allowsUserDefault(ClientIdentityField.VERSION.key())).isFalse();
    }

    @Test
    void theRiskyAlwaysRedirectModeNeverBecomesAUserDefault() {
        assertThat(SettingKey.allowsUserDefault("mcp.redirect.mode", RedirectMode.ALWAYS.name())).isFalse();
        assertThat(SettingKey.allowsUserDefault("mcp.redirect.mode", RedirectMode.SAME_ORIGIN.name())).isTrue();
    }

    @Test
    void anUndeclaredKeyNeverTakesAUserDefault() {
        assertThat(SettingKey.declaring("mcp.something.new")).isEmpty();
        assertThat(SettingKey.allowsUserDefault("mcp.something.new")).isFalse();
    }

    @Test
    void aFamilyNeedsAMemberAndASingleKeyHasNone() {
        assertThat(SettingKey.CHECK_ENABLED.key("ssrf")).isEqualTo("mcp.check.ssrf.enabled");
        assertThat(SettingKey.declaring("mcp.check..enabled")).isEmpty();
        assertThatThrownBy(SettingKey.CHECK_ENABLED::key).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> SettingKey.ENDPOINT.key("x")).isInstanceOf(IllegalStateException.class);
    }
}
