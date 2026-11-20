package com.mcpscanner.config;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.core.oauth.RegistrationMode;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.InMemoryPreferences;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class UserDefaultSettingsTest {

    private static final Set<String> NOT_SETTERS = Set.of("saveAsUserDefaults", "resetUserDefaults");

    private PersistedObject project;
    private InMemoryPreferences preferences;
    private ExtensionConfigStore config;

    @BeforeEach
    void setUp() {
        project = InMemoryPersistedObject.create();
        preferences = new InMemoryPreferences();
        config = newProjectConfig();
    }

    @Test
    void aFreshProjectStartsFromTheSavedUserDefaults() {
        config.setRedirectMode(RedirectMode.SAME_ORIGIN);
        config.setCheckEnabled("ssrf", false);
        config.setResourceCap(ResourceCap.EXTENSION_SCAN_WORKERS, 20L);
        config.setOauthRedirectPort(8123);
        config.setScanMode("MCP_AND_BURP");
        config.saveAsUserDefaults();

        ExtensionConfigStore fresh = freshProjectConfig();

        assertThat(fresh.redirectMode()).isEqualTo(RedirectMode.SAME_ORIGIN);
        assertThat(fresh.checkEnabled("ssrf")).isFalse();
        assertThat(fresh.extensionScanWorkers()).isEqualTo(20);
        assertThat(fresh.oauthRedirectPort()).isEqualTo(8123);
        assertThat(fresh.scanMode()).isEqualTo("MCP_AND_BURP");
    }

    @Test
    void savingDefaultsElsewhereLeavesAnExistingProjectsSettingsUnchanged() {
        project.setString("mcp.endpoint", "https://target.example/mcp");
        ExtensionConfigStore existing = newProjectConfig();
        RedirectMode before = existing.redirectMode();

        ExtensionConfigStore other = freshProjectConfig();
        other.setRedirectMode(RedirectMode.SAME_ORIGIN);
        other.setCheckEnabled("ssrf", false);
        other.saveAsUserDefaults();

        assertThat(existing.redirectMode()).isEqualTo(before);
        assertThat(existing.checkEnabled("ssrf")).isNull();
    }

    @Test
    void aReleasedProjectThatStoredOnlyItsChangedKeysLoadsAsItDidBefore() {
        preferences.setString("mcp.redirect.mode", RedirectMode.SAME_ORIGIN.name());
        preferences.setBoolean("mcp.check.ssrf.enabled", false);
        preferences.setLong("mcp.scan.engine_workers", 20L);
        project = InMemoryPersistedObject.create();
        project.setString("mcp.endpoint", "https://target.example/mcp");
        project.setBoolean("mcp.check.xss.enabled", false);

        ExtensionConfigStore released = newProjectConfig();

        assertThat(released.redirectMode()).isEqualTo(RedirectMode.METHOD_PRESERVING_SAME_ORIGIN);
        assertThat(released.checkEnabled("ssrf")).isNull();
        assertThat(released.checkEnabled("xss")).isFalse();
        assertThat(released.extensionScanWorkers()).isEqualTo(10);
    }

    @Test
    void aProjectOpenedBeforeAnyDefaultsWereSavedIgnoresDefaultsSavedLater() {
        ExtensionConfigStore openedEarlier = freshProjectConfig();

        preferences.setString("mcp.redirect.mode", RedirectMode.SAME_ORIGIN.name());

        assertThat(openedEarlier.redirectMode()).isEqualTo(RedirectMode.METHOD_PRESERVING_SAME_ORIGIN);
        assertThat(newProjectConfig().redirectMode()).isEqualTo(RedirectMode.METHOD_PRESERVING_SAME_ORIGIN);
    }

    @Test
    void aNewProjectKeepsItsSeededDefaultsAfterTheDefaultsChange() {
        preferences.setString("mcp.redirect.mode", RedirectMode.SAME_ORIGIN.name());
        ExtensionConfigStore seeded = freshProjectConfig();

        preferences.setString("mcp.redirect.mode", RedirectMode.METHOD_PRESERVING_SAME_ORIGIN.name());

        assertThat(seeded.redirectMode()).isEqualTo(RedirectMode.SAME_ORIGIN);
        assertThat(newProjectConfig().redirectMode()).isEqualTo(RedirectMode.SAME_ORIGIN);
    }

    @Test
    void theRegistrationModeIsNeverCarriedIntoANewProject() {
        config.setOauthRegistrationMode(RegistrationMode.PRE_REGISTERED);
        config.setOauthClientId("engagement-client");
        config.saveAsUserDefaults();
        assertThat(freshProjectConfig().oauthRegistrationMode()).isEqualTo(RegistrationMode.AUTO);

        preferences.setString("mcp.oauth.registration_mode", RegistrationMode.PRE_REGISTERED.name());
        assertThat(freshProjectConfig().oauthRegistrationMode()).isEqualTo(RegistrationMode.AUTO);
    }

    @Test
    void withoutAUserDefaultTheBuiltInDefaultApplies() {
        assertThat(config.redirectMode()).isEqualTo(RedirectMode.METHOD_PRESERVING_SAME_ORIGIN);
        assertThat(config.oauthRegistrationMode()).isEqualTo(RegistrationMode.AUTO);
        assertThat(config.extensionScanWorkers()).isEqualTo(10);
        assertThat(config.answerServerPings()).isTrue();
    }

    @Test
    void projectOnlySettingsFoundInPreferencesAreNeverRead() {
        preferences.setString("mcp.endpoint", "https://other-engagement.example/mcp");
        preferences.setString("mcp.mining.write_tools", "ALL");
        preferences.setBoolean("mcp.mining.mined_in_write_tools", true);
        preferences.setString("mcp.identities", "[]");
        preferences.setString("mcp.oauth.client_id", "other-client");

        ExtensionConfigStore fresh = freshProjectConfig();

        assertThat(fresh.endpoint()).isNull();
        assertThat(fresh.miningWriteTools()).isNull();
        assertThat(fresh.minedIdsInWriteTools()).isFalse();
        assertThat(fresh.identitiesJson()).isNull();
        assertThat(fresh.oauthClientId()).isNull();
    }

    @Test
    void noSetterWritesToPreferences() throws Exception {
        callEverySetter(config);

        assertThat(preferences.allKeys()).isEmpty();
    }

    @Test
    void everyKeyASetterWritesHasADeclaredScope() throws Exception {
        callEverySetter(config);

        assertThat(projectKeys()).isNotEmpty()
                .allSatisfy(key -> assertThat(SettingKey.declaring(key)).as(key).isPresent());
    }

    @Test
    void savingAsUserDefaultsNeverWritesAProjectOnlySetting() throws Exception {
        callEverySetter(config);

        config.saveAsUserDefaults();

        assertThat(preferences.allKeys()).isNotEmpty()
                .allSatisfy(key -> assertThat(SettingKey.allowsUserDefault(key)).as(key).isTrue());
        assertThat(projectKeys().stream().filter(SettingKey::allowsUserDefault))
                .containsExactlyInAnyOrderElementsOf(preferences.allKeys());
    }

    @Test
    void resettingUserDefaultsClearsThemButKeepsThisProjectAsItIs() {
        preferences.setString("mcp.redirect.mode", RedirectMode.SAME_ORIGIN.name());
        preferences.setBoolean("mcp.check.ssrf.enabled", false);
        preferences.setString("mcp.oauth.registration_mode", RegistrationMode.PRE_REGISTERED.name());
        ExtensionConfigStore seeded = freshProjectConfig();
        seeded.setCheckEnabled("ssrf", true);

        seeded.resetUserDefaults();

        assertThat(preferences.allKeys()).isEmpty();
        assertThat(seeded.redirectMode()).isEqualTo(RedirectMode.SAME_ORIGIN);
        assertThat(seeded.checkEnabled("ssrf")).isTrue();
        assertThat(freshProjectConfig().redirectMode()).isEqualTo(RedirectMode.METHOD_PRESERVING_SAME_ORIGIN);
    }

    @Test
    void clientIdentityFollowsTheUserDefault() {
        config.saveClientIdentity(ClientIdentity.from(field -> field == ClientIdentityField.NAME ? "my-client" : ""));
        config.saveAsUserDefaults();

        assertThat(freshProjectConfig().clientIdentity().value(ClientIdentityField.NAME)).isEqualTo("my-client");
    }

    @Test
    void theRiskyAlwaysRedirectModeStaysInItsProject() {
        config.setRedirectMode(RedirectMode.ALWAYS);
        config.saveAsUserDefaults();
        assertThat(freshProjectConfig().redirectMode()).isEqualTo(RedirectMode.METHOD_PRESERVING_SAME_ORIGIN);

        preferences.setString("mcp.redirect.mode", RedirectMode.ALWAYS.name());
        assertThat(freshProjectConfig().redirectMode()).isEqualTo(RedirectMode.METHOD_PRESERVING_SAME_ORIGIN);
    }

    @Test
    void savingAlwaysReplacesAnEarlierSafeRedirectDefault() {
        preferences.setString("mcp.redirect.mode", RedirectMode.SAME_ORIGIN.name());
        config.setRedirectMode(RedirectMode.ALWAYS);

        config.saveAsUserDefaults();

        assertThat(preferences.getString("mcp.redirect.mode")).isNull();
    }

    @Test
    void theClientVersionIsNotCarriedIntoNewProjects() {
        config.saveClientIdentity(ClientIdentity.from(field -> field == ClientIdentityField.VERSION ? "0.1" : ""));
        config.saveAsUserDefaults();

        assertThat(freshProjectConfig().clientIdentity().value(ClientIdentityField.VERSION))
                .isEqualTo(ClientIdentityField.VERSION.defaultValue());
    }

    private ExtensionConfigStore newProjectConfig() {
        return new ExtensionConfigStore(project, preferences, mock(Logging.class));
    }

    private ExtensionConfigStore freshProjectConfig() {
        project = InMemoryPersistedObject.create();
        return newProjectConfig();
    }

    private Set<String> projectKeys() {
        Set<String> keys = new HashSet<>();
        Stream.of(project.stringKeys(), project.booleanKeys(), project.integerKeys(), project.longKeys())
                .forEach(keys::addAll);
        return keys;
    }

    private static void callEverySetter(ExtensionConfigStore config) throws Exception {
        for (Method method : ExtensionConfigStore.class.getDeclaredMethods()) {
            if (isSetter(method)) {
                for (Object[] arguments : argumentsFor(method)) {
                    invoke(config, method, arguments);
                }
            }
        }
    }

    private static boolean isSetter(Method method) {
        return Modifier.isPublic(method.getModifiers()) && !NOT_SETTERS.contains(method.getName())
                && Stream.of("set", "save", "retire", "mark").anyMatch(method.getName()::startsWith);
    }

    private static List<Object[]> argumentsFor(Method method) {
        List<Object[]> combinations = new ArrayList<>();
        combinations.add(new Object[0]);
        for (Class<?> type : method.getParameterTypes()) {
            List<Object[]> extended = new ArrayList<>();
            for (Object[] prefix : combinations) {
                for (Object sample : samplesOf(type, method)) {
                    Object[] next = Arrays.copyOf(prefix, prefix.length + 1);
                    next[prefix.length] = sample;
                    extended.add(next);
                }
            }
            combinations = extended;
        }
        return combinations;
    }

    private static List<?> samplesOf(Class<?> type, Method method) {
        Map<Class<?>, List<?>> samples = Map.of(
                String.class, List.of("https://target.example/value"),
                boolean.class, List.of(false),
                int.class, List.of(8123),
                Long.class, List.of(1L),
                ResourceCap.class, List.of(ResourceCap.values()),
                RedirectMode.class, List.of(RedirectMode.SAME_ORIGIN),
                RegistrationMode.class, List.of(RegistrationMode.PRE_REGISTERED),
                List.class, List.of(List.of(new ExtensionConfigStore.PersistedScope("read", true, "user"))),
                ClientIdentity.class, List.of(ClientIdentity.from(field -> "https://client.example/" + field.wireName())));
        List<?> found = samples.get(type);
        assertThat(found).as("add a sample for %s, used by %s", type, method.getName()).isNotNull();
        return found;
    }

    private static void invoke(ExtensionConfigStore config, Method method, Object[] arguments) throws Exception {
        try {
            method.invoke(config, arguments);
        } catch (InvocationTargetException failure) {
            throw new AssertionError(method.getName() + " failed", failure.getCause());
        }
    }
}
