package com.mcpscanner.identity;

import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IdentityRegistryTest {

    private ExtensionConfigStore config;
    private IdentityRegistry registry;
    private Identity userOne;

    @BeforeEach
    void setUp() {
        config = InMemoryPersistedObject.configStore();
        registry = new IdentityRegistry(store());
        userOne = registry.primaryUser();
    }

    @Test
    void aNewProjectConnectsAsAPersistedUserOne() {
        assertThat(registry.identities()).containsExactly(userOne);
        assertThat(userOne.name()).isEqualTo("User 1");
        assertThat(userOne.authKind()).isEqualTo(IdentityAuthKind.DETECT);
        assertThat(new IdentityRegistry(store()).primaryUser()).isEqualTo(userOne);
    }

    @Test
    void otherUserCountExcludesThePrimaryUser() {
        assertThat(registry.otherUserCount()).isZero();

        registry.add(peer("bob"));

        assertThat(registry.otherUserCount()).isEqualTo(1);
    }

    @Test
    void aPrimaryUserSetToAuthNoneAfterTheMigrationStaysAuthNone() {
        registry.update(userOne.withAuthKind(IdentityAuthKind.NONE));

        assertThat(new IdentityRegistry(store()).primaryUser().authKind()).isEqualTo(IdentityAuthKind.NONE);
    }

    @Test
    void makingAnotherUserPrimaryTurnsADetectingFormerPrimaryIntoAuthNone() {
        Identity bob = registry.add(peer("bob"));
        registry.setCredential(userOne.id(), new BearerTokenAuthStrategy("detected-session"));

        registry.makePrimary(bob.id());

        assertThat(registry.require(userOne.id()).authKind()).isEqualTo(IdentityAuthKind.NONE);
        assertThat(registry.credential(userOne.id())).isEmpty();
    }

    @Test
    void aDetectedOutcomeIsForgottenWhenTheKindOrCredentialChanges() {
        registry.recordDetected(userOne.id(), IdentityAuthKind.NONE);
        assertThat(registry.detected(userOne.id())).contains(IdentityAuthKind.NONE);

        registry.update(userOne.withAuthKind(IdentityAuthKind.BEARER));
        assertThat(registry.detected(userOne.id())).isEmpty();

        registry.recordDetected(userOne.id(), IdentityAuthKind.OAUTH);
        registry.setCredential(userOne.id(), new BearerTokenAuthStrategy("session"));
        registry.removeCredential(userOne.id());
        assertThat(registry.detected(userOne.id())).isEmpty();
    }

    @Test
    void anAddedUserCannotDetectAutomatically() {
        Identity added = registry.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.DETECT));

        assertThat(added.authKind()).isEqualTo(IdentityAuthKind.NONE);
        assertThat(registry.require(added.id()).authKind()).isEqualTo(IdentityAuthKind.NONE);
    }

    @Test
    void aCopyOfADetectingUserSendsNoCredentials() {
        Identity copy = registry.duplicate(userOne.id());

        assertThat(copy.authKind()).isEqualTo(IdentityAuthKind.NONE);
    }

    @Test
    void makingAnotherUserPrimaryTurnsAnOAuthGrantFormerPrimaryIntoAuthNone() {
        registry.update(userOne.withAuthKind(IdentityAuthKind.OAUTH_CLIENT_CREDENTIALS));
        Identity bob = registry.add(peer("bob"));

        registry.makePrimary(bob.id());

        assertThat(registry.require(userOne.id()).authKind()).isEqualTo(IdentityAuthKind.NONE);
    }

    @Test
    void anAddedOrCopiedUserCannotUseAnOAuthGrant() {
        Identity added = registry.add(Identity.create("bob", IdentityRole.PEER,
                IdentityAuthKind.OAUTH_ENTERPRISE_MANAGED));
        registry.update(userOne.withAuthKind(IdentityAuthKind.OAUTH_CLIENT_CREDENTIALS));

        assertThat(added.authKind()).isEqualTo(IdentityAuthKind.NONE);
        assertThat(registry.duplicate(userOne.id()).authKind()).isEqualTo(IdentityAuthKind.NONE);
    }

    @Test
    void aSavedClientCredentialsGrantBecomesThePrimaryUsersKindOnce() {
        config = InMemoryPersistedObject.configStore();
        config.setOauthGrant("CLIENT_CREDENTIALS");
        config.setAuthType("OAuth 2.1");

        IdentityRegistry migrated = new IdentityRegistry(store());

        assertThat(migrated.primaryUser().authKind()).isEqualTo(IdentityAuthKind.OAUTH_CLIENT_CREDENTIALS);
        assertThat(config.oauthGrant()).isNull();
        migrated.update(migrated.primaryUser().withAuthKind(IdentityAuthKind.BEARER));
        config.setOauthGrant("CLIENT_CREDENTIALS");
        assertThat(new IdentityRegistry(store()).primaryUser().authKind()).isEqualTo(IdentityAuthKind.BEARER);
    }

    @Test
    void connectAsSwitchesTheUserPersistsAndNotifies() {
        Identity bob = registry.add(peer("bob"));
        AtomicInteger changes = new AtomicInteger();
        registry.addListener(changes::incrementAndGet);

        registry.makePrimary(bob.id());
        registry.makePrimary(bob.id());

        assertThat(registry.primaryUser()).isEqualTo(bob);
        assertThat(registry.isPrimary(bob.id())).isTrue();
        assertThat(registry.isPrimary(userOne.id())).isFalse();
        assertThat(new IdentityRegistry(store()).primaryUser()).isEqualTo(bob);
        assertThat(changes).hasValue(1);
    }

    @Test
    void connectingAsAnUnknownUserFails() {
        assertThatThrownBy(() -> registry.makePrimary("missing"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(registry.primaryUser()).isEqualTo(userOne);
    }

    @Test
    void theConnectAsUserCannotBeRemoved() {
        assertThatThrownBy(() -> registry.remove(userOne.id()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Make another user primary before removing User 1");
        assertThat(registry.identities()).containsExactly(userOne);
    }

    @Test
    void thePrimaryUserIsTheBaselineSoItIsNeverCompared() {
        registry.update(userOne.withAuthKind(IdentityAuthKind.NONE));
        Identity bob = registry.add(peer("bob"));
        registry.setCredential(userOne.id(), new NoAuthStrategy());
        registry.setCredential(bob.id(), new NoAuthStrategy());

        assertThat(registry.compared()).containsExactly(bob);
        assertThat(registry.otherUsers()).containsExactly(bob);

        registry.makePrimary(bob.id());

        assertThat(registry.compared()).containsExactly(registry.require(userOne.id()));
    }

    @Test
    void anyCredentialReportsWhetherAnyUserHoldsALiveCredential() {
        Identity bob = registry.add(peer("bob"));
        assertThat(registry.hasAnyCredential()).isFalse();

        registry.setCredential(bob.id(), new NoAuthStrategy());

        assertThat(registry.hasAnyCredential()).isTrue();
    }

    @Test
    void startsWithThePersistedIdentities() {
        Identity bob = registry.add(peer("bob"));

        assertThat(new IdentityRegistry(store()).identities()).containsExactly(userOne, bob);
    }

    @Test
    void keepsIdentitiesInTheOrderTheyWereAdded() {
        Identity bob = registry.add(peer("bob"));
        Identity carol = registry.add(peer("carol"));

        assertThat(registry.identities()).containsExactly(userOne, bob, carol);
        assertThat(registry.find(carol.id())).contains(carol);
        assertThat(registry.find("missing")).isEmpty();
    }

    @Test
    void rejectsBlankAndDuplicateNames() {
        registry.add(peer("bob"));

        assertThatThrownBy(() -> registry.add(peer("  ")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> registry.add(peer(" Bob ")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void updateReplacesTheIdentityInPlaceAndPersists() {
        Identity bob = registry.add(peer("bob"));
        Identity carol = registry.add(peer("carol"));

        Identity renamed = bob.withName("robert");
        registry.update(renamed);

        assertThat(registry.identities()).containsExactly(userOne, renamed, carol);
        assertThat(new IdentityRegistry(store()).identities()).containsExactly(userOne, renamed, carol);
    }

    @Test
    void updateMayKeepItsOwnNameButNotTakeAnother() {
        Identity bob = registry.add(peer("bob"));
        registry.add(peer("carol"));

        registry.update(bob.withPrivateMarker("marker"));

        assertThatThrownBy(() -> registry.update(bob.withName("carol")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void updatingAnUnknownIdentityFails() {
        assertThatThrownBy(() -> registry.update(peer("ghost")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void removeDropsTheIdentityAndItsLiveCredential() {
        Identity bob = registry.add(peer("bob"));
        registry.setCredential(bob.id(), new BearerTokenAuthStrategy("bob-token"));

        registry.remove(bob.id());

        assertThat(registry.identities()).containsExactly(userOne);
        assertThat(registry.credential(bob.id())).isEmpty();
        assertThat(new IdentityRegistry(store()).identities()).containsExactly(userOne);
    }

    @Test
    void duplicateAddsACopyWithAFreshIdAndCopyName() {
        Identity bob = registry.add(peer("bob"));

        Identity copy = registry.duplicate(bob.id());
        Identity secondCopy = registry.duplicate(bob.id());

        assertThat(copy.id()).isNotEqualTo(bob.id());
        assertThat(copy.name()).isEqualTo("bob copy");
        assertThat(secondCopy.name()).isEqualTo("bob copy 2");
        assertThat(registry.identities()).containsExactly(userOne, bob, copy, secondCopy);
    }

    @Test
    void credentialsAreHeldPerIdentityAndClearedOnDisconnect() {
        Identity bob = registry.add(peer("bob"));
        NoAuthStrategy credential = new NoAuthStrategy();

        registry.setCredential(bob.id(), credential);

        assertThat(registry.credential(bob.id())).containsSame(credential);
        registry.clearCredentials();
        assertThat(registry.credential(bob.id())).isEmpty();
    }

    @Test
    void settingACredentialForAnUnknownIdentityFails() {
        assertThatThrownBy(() -> registry.setCredential("missing", new NoAuthStrategy()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void comparedIdentitiesAreThoseFlaggedForComparisonWithALiveCredential() {
        Identity bob = registry.add(peer("bob"));
        Identity carol = registry.add(peer("carol"));
        Identity dave = registry.add(peer("dave").withCompared(false));
        registry.setCredential(bob.id(), new NoAuthStrategy());
        registry.setCredential(dave.id(), new NoAuthStrategy());

        assertThat(registry.compared()).containsExactly(bob);
        assertThat(carol.compared()).isTrue();
    }

    @Test
    void everyChangeNotifiesListeners() {
        AtomicInteger changes = new AtomicInteger();
        registry.addListener(changes::incrementAndGet);

        Identity bob = registry.add(peer("bob"));
        registry.update(bob.withPrivateMarker("m"));
        registry.setCredential(bob.id(), new NoAuthStrategy());
        registry.duplicate(bob.id());
        registry.clearCredentials();
        registry.remove(bob.id());

        assertThat(changes.get()).isEqualTo(6);
    }

    @Test
    void persistsNoLiveCredentialText() {
        Identity bob = registry.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        registry.setCredential(bob.id(), new BearerTokenAuthStrategy("super-secret-bob-token"));
        registry.update(bob.withPrivateMarker("bob-marker"));

        assertThat(config.identitiesJson()).contains("bob-marker").doesNotContain("super-secret-bob-token");
    }

    private IdentityStore store() {
        return new IdentityStore(config, McpEventLog.noop());
    }

    @Test
    void removingACredentialStopsComparingTheIdentityAndNotifies() {
        Identity bob = registry.add(peer("bob"));
        registry.setCredential(bob.id(), new BearerTokenAuthStrategy("bob"));
        AtomicInteger changes = new AtomicInteger();
        registry.addListener(changes::incrementAndGet);

        registry.removeCredential(bob.id());
        registry.removeCredential(bob.id());

        assertThat(registry.compared()).isEmpty();
        assertThat(changes).hasValue(1);
    }

    @Test
    void requireReturnsTheIdentityOrRejectsAnUnknownId() {
        Identity bob = registry.add(peer("bob"));

        assertThat(registry.require(bob.id())).isEqualTo(bob);
        assertThatThrownBy(() -> registry.require("missing"))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Unknown identity: missing");
    }

    private static Identity peer(String name) {
        return Identity.create(name, IdentityRole.PEER, IdentityAuthKind.BEARER);
    }

    @Test
    void aRemovedListenerIsNoLongerNotified() {
        AtomicInteger changes = new AtomicInteger();
        Runnable listener = changes::incrementAndGet;
        registry.addListener(listener);

        registry.removeListener(listener);
        registry.add(peer("bob"));

        assertThat(changes).hasValue(0);
    }
}
