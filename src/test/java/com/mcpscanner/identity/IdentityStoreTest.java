package com.mcpscanner.identity;

import com.mcpscanner.testutil.InMemoryPreferences;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.config.AuthTypeNames;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class IdentityStoreTest {

    private static final String LEGACY_PRIMARY_KEY = "mcp.identities.primary";
    private static final String ALICE_PROFILE = "{\"privateMarker\":\"ALICE-PRIVATE\","
            + "\"ownedObjects\":[{\"argument\":\"doc_id\",\"value\":\"d-alice-0001\"}]}";

    private PersistedObject persisted;
    private ExtensionConfigStore config;
    private McpEventLog eventLog;
    private IdentityStore store;

    @BeforeEach
    void setUp() {
        persisted = InMemoryPersistedObject.create();
        config = new ExtensionConfigStore(persisted, new InMemoryPreferences(), mock(Logging.class));
        eventLog = mock(McpEventLog.class);
        store = new IdentityStore(config, eventLog);
    }

    @Test
    void nothingSavedLoadsAsAnEmptyListWithNoConnectAsUser() {
        StoredIdentities loaded = store.load();

        assertThat(loaded.identities()).isEmpty();
        assertThat(loaded.primaryId()).isEmpty();
    }

    @Test
    void savedIdentitiesLoadBackUnchangedAndInOrder() {
        Identity bob = Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.CUSTOM_HEADERS)
                .withPrivateMarker("bob-marker")
                .withOwnedValues(OwnedValues.of(List.of(new EnteredValue("zeta_id", "9"),
                        new EnteredValue("alpha_id", "1"), new MinedValue("doc_id", "d-1",
                                new MinedSource("tools/call list_documents", "items[0].doc_id"), ValueScope.SHARED))))
                .withHeaderNames(List.of("X-Api-Key"));
        Identity carol = Identity.create("carol", IdentityRole.LOWER, IdentityAuthKind.OAUTH)
                .withOAuth(new IdentityOAuthSettings("https://issuer.example", "client-1", List.of("read")));

        store.save(StoredIdentities.of(List.of(bob, carol), carol.id()));

        StoredIdentities loaded = new IdentityStore(config, eventLog).load();
        assertThat(loaded.identities()).containsExactly(bob, carol);
        assertThat(loaded.primaryId()).contains(carol.id());
    }

    @Test
    void ownedObjectsSavedBeforeProvenanceExistedLoadAsEnteredValues() {
        config.setIdentitiesJson("[{\"id\":\"b\",\"name\":\"bob\",\"role\":\"PEER\",\"authKind\":\"BEARER\","
                + "\"compared\":true,\"ownedObjects\":[{\"argument\":\"doc_id\",\"value\":\"d-bob-1\"}]}]");

        assertThat(store.load().identities()).singleElement().extracting(Identity::ownedValues)
                .isEqualTo(OwnedValues.entered(Map.of("doc_id", "d-bob-1")));
    }

    @Test
    void savedOwnedValuesCarryNoReplyTextOrCredentials() {
        saveOnly(bob().withOwnedValues(OwnedValues.of(List.of(new MinedValue("doc_id", "d-1",
                new MinedSource("tools/call list_documents", "items[0].doc_id"), ValueScope.PRIVATE)))));

        assertThat(config.identitiesJson()).contains("\"provenance\":\"MINED\"", "\"scope\":\"PRIVATE\"",
                "\"operation\":\"tools/call list_documents\"", "\"fieldPath\":\"items[0].doc_id\"");
    }

    @Test
    void aNoCredentialsUserLoadsBack() {
        Identity anonymous = Identity.create("User 1", IdentityRole.PEER, IdentityAuthKind.NONE);

        saveOnly(anonymous);

        assertThat(store.load().identities()).containsExactly(anonymous);
    }

    @Test
    void identitiesAreStoredUnderTheirOwnKey() {
        saveOnly(bob());

        assertThat(config.identitiesJson()).contains("bob");
    }

    @Test
    void corruptJsonLogsAWarningAndLoadsEmpty() {
        config.setIdentitiesJson("{not json");

        assertThat(store.load().identities()).isEmpty();
        verify(eventLog).warn(contains("identities"));
    }

    @Test
    void unknownPersistedFieldsAreIgnored() {
        saveOnly(bob());
        config.setIdentitiesJson(config.identitiesJson().replace("{\"id\"", "{\"addedLater\":true,\"id\""));

        assertThat(store.load().identities()).extracting(Identity::name).containsExactly("bob");
    }

    @Test
    void anUnreadableDocumentIsKeptAsABackupWhenIdentitiesAreSaved() {
        config.setIdentitiesJson("[{\"role\":\"FROM_A_NEWER_BUILD\"}]");
        store.load();

        saveOnly(bob());

        assertThat(config.unreadableIdentitiesBackupJson()).isEqualTo("[{\"role\":\"FROM_A_NEWER_BUILD\"}]");
        assertThat(store.load().identities()).extracting(Identity::name).containsExactly("bob");
        verify(eventLog).warn(contains("backup"));
    }

    @Test
    void aReadableDocumentIsNotBackedUp() {
        saveOnly(bob());
        store.save(StoredIdentities.of(List.of(), null));

        assertThat(config.unreadableIdentitiesBackupJson()).isNull();
    }

    @Test
    void anIdentityThatReusedThePrimaryAuthTakesTheSavedAuthenticationKind() {
        config.setAuthType(AuthTypeNames.CUSTOM_HEADERS);
        config.setIdentitiesJson("[{\"id\":\"b\",\"name\":\"bob\",\"role\":\"PEER\","
                + "\"authKind\":\"SAME_AS_PRIMARY\",\"compared\":true}]");

        assertThat(store.load().identities()).singleElement()
                .extracting(Identity::authKind).isEqualTo(IdentityAuthKind.CUSTOM_HEADERS);
    }

    @Test
    void theLegacyPrimaryCarriesTheSavedAuthenticationKindAndProfile() {
        config.setAuthType(AuthTypeNames.BEARER);
        persisted.setString(LEGACY_PRIMARY_KEY, ALICE_PROFILE);

        LegacyPrimary legacy = store.legacyPrimary();

        assertThat(legacy.authKind()).isEqualTo(IdentityAuthKind.BEARER);
        assertThat(legacy.privateMarker()).contains("ALICE-PRIVATE");
        assertThat(legacy.ownedValues()).isEqualTo(OwnedValues.entered(Map.of("doc_id", "d-alice-0001")));
    }

    @Test
    void aCorruptLegacyPrimaryProfileLogsAWarningAndCarriesNothing() {
        persisted.setString(LEGACY_PRIMARY_KEY, "{not json");

        LegacyPrimary legacy = store.legacyPrimary();

        assertThat(legacy.privateMarker()).isEqualTo(Optional.empty());
        assertThat(legacy.ownedValues().isEmpty()).isTrue();
        verify(eventLog).warn(contains("primary"));
    }

    @Test
    void clearingTheLegacyPrimaryRemovesTheOldProfile() {
        persisted.setString(LEGACY_PRIMARY_KEY, ALICE_PROFILE);

        store.clearLegacyPrimary();

        assertThat(config.primaryProfileJson()).isNull();
        assertThat(store.legacyPrimary().privateMarker()).isEmpty();
    }

    @Test
    void migratingUserOneClearsTheLegacyPrimaryOnceUserOneIsSaved() {
        persisted.setString(LEGACY_PRIMARY_KEY, ALICE_PROFILE);

        Identity userOne = new IdentityRegistry(store).primaryUser();

        assertThat(userOne.privateMarker()).contains("ALICE-PRIVATE");
        assertThat(config.primaryProfileJson()).isNull();
        assertThat(new IdentityStore(config, eventLog).load().identities()).containsExactly(userOne);
    }

    private void saveOnly(Identity identity) {
        store.save(StoredIdentities.of(List.of(identity), identity.id()));
    }

    private static Identity bob() {
        return Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
    }
}
