package com.mcpscanner.automation;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.access.WriteReplayConfirmations;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.OwnedValues;
import com.mcpscanner.identity.IdentityRosterSource;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IdentityHandoverTest {

    private static final CommandAuth ALICE_TOKEN = new CommandAuth("alice-token", null);
    private static final AccessItemKey LIST_TARGETS = new AccessItemKey(AccessItemKey.Kind.TOOL, "list_targets");
    private static final List<McpToolDefinition> TOOLS = List.of(tool("get_campaign"), tool("list_targets"));

    private final IdentityRegistry registry = new IdentityRegistry(
            new IdentityStore(InMemoryPersistedObject.configStore(), McpEventLog.noop()));
    private final WriteReplayConfirmations confirmations = new WriteReplayConfirmations();
    private final Map<AccessItemKey, AccessExpectation> expectations = new HashMap<>();
    private final AtomicReference<List<SeedCall>> handedSeeds = new AtomicReference<>();
    private final IdentityHandover handover = new IdentityHandover(registry, confirmations, expectations::put,
            handedSeeds::set);

    @Test
    void connectsAsTheNamedUserWithItsMarkerOwnedObjectsAndCredential() {
        handover.beforeConnect(aliceAndBob(), ALICE_TOKEN, ALICE_TOKEN.strategy());

        Identity alice = registry.primaryUser();
        assertThat(alice.name()).isEqualTo("alice");
        assertThat(alice.authKind()).isEqualTo(IdentityAuthKind.BEARER);
        assertThat(alice.privateMarker()).contains("ALICE_ONLY");
        assertThat(alice.ownedValues()).isEqualTo(OwnedValues.entered(Map.of("id", "a-1")));
        assertThat(registry.credential(alice.id())).hasValueSatisfying(credential ->
                assertThat(credential.headers()).containsEntry("Authorization", "Bearer alice-token"));
    }

    @Test
    void comparesEveryOtherUserWithItsOwnCredentialInTheCheckRoster() {
        handover.beforeConnect(aliceAndBob(), ALICE_TOKEN, ALICE_TOKEN.strategy());

        PrincipalRoster roster = new IdentityRosterSource(new CurrentAuthHolder(), registry).get();
        assertThat(roster.primary().ownedObjects().all()).containsExactly(Map.entry("id", "a-1"));
        assertThat(roster.compared()).singleElement().satisfies(bob -> {
            assertThat(bob.name()).isEqualTo("bob");
            assertThat(bob.role()).isEqualTo(PrincipalRole.PEER);
            assertThat(bob.credentialHeaders().get()).containsExactly(Map.entry("X-Api-Key", "bob-key"));
            assertThat(bob.privateMarker()).contains("BOB_ONLY");
            assertThat(bob.ownedObjects().all()).containsExactly(Map.entry("id", "b-1"));
        });
        assertThat(registry.find(roster.compared().get(0).id())).hasValueSatisfying(bob ->
                assertThat(bob.headerNames()).containsExactly("X-Api-Key"));
    }

    @Test
    void replacesTheUsersAnEarlierCommandHandedOver() {
        handover.beforeConnect(aliceAndBob(), ALICE_TOKEN, ALICE_TOKEN.strategy());

        handover.beforeConnect(new CommandIdentities(user("alice", null, null), List.of(
                user("carol", IdentityRole.LOWER, new CommandAuth("carol-token", null))), null, null, null),
                ALICE_TOKEN, ALICE_TOKEN.strategy());

        assertThat(registry.otherUsers()).extracting(Identity::name).containsExactly("carol");
        assertThat(registry.primaryUser().privateMarker()).isEmpty();
    }

    @Test
    void aCommandWithoutIdentitiesLeavesOnlyTheConnectAsUser() {
        handover.beforeConnect(aliceAndBob(), ALICE_TOKEN, ALICE_TOKEN.strategy());

        handover.beforeConnect(CommandIdentities.NONE, ALICE_TOKEN, ALICE_TOKEN.strategy());

        assertThat(registry.otherUsers()).isEmpty();
        assertThat(registry.primaryUser().name()).isEqualTo("alice");
    }

    @Test
    void confirmsTheNamedWriteToolsFromTheConnectedInventoryAndStoresExpectations() {
        handover.afterConnect(aliceAndBob(), TOOLS);

        assertThat(confirmations.confirmed("get_campaign")).isTrue();
        assertThat(confirmations.confirmed("list_targets")).isFalse();
        assertThat(expectations).containsExactly(Map.entry(LIST_TARGETS, AccessExpectation.SHARED_BY_DESIGN));
    }

    @Test
    void handsTheItemSeedsOnAfterConnect() {
        handover.afterConnect(aliceAndBob(), TOOLS);

        assertThat(handedSeeds.get()).isEqualTo(aliceAndBob().itemSeeds());
    }

    @Test
    void aLaterCommandWithoutItemSeedsHandsOnNone() {
        handover.afterConnect(aliceAndBob(), TOOLS);

        handover.afterConnect(CommandIdentities.NONE, TOOLS);

        assertThat(handedSeeds.get()).isEmpty();
    }

    @Test
    void refusesToConfirmAToolTheServerDoesNotList() {
        CommandIdentities unknown = new CommandIdentities(null, null, Set.of("drop_tables"), null, null);

        assertThatThrownBy(() -> handover.afterConnect(unknown, TOOLS))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("drop_tables");
    }

    @Test
    void readsTheIdentitiesFromTheCommandJson() throws Exception {
        String json = """
                {"endpoint": "http://target/mcp", "identities": {
                  "connectAs": {"name": "alice", "privateMarker": "ALICE_ONLY", "ownedObjects": {"id": "a-1"}},
                  "others": [{"name": "bob", "role": "PEER", "auth": {"headers": {"X-Api-Key": "bob-key"}},
                              "privateMarker": "BOB_ONLY", "ownedObjects": {"id": "b-1"}}],
                  "confirmedWrites": ["get_campaign"],
                  "expectations": [{"item": {"kind": "TOOL", "name": "list_targets"},
                                    "expectation": "SHARED_BY_DESIGN"}],
                  "itemSeeds": [{"method": "tools/call",
                                 "params": {"name": "get_campaign", "arguments": {"id": "a-1", "limit": 2}}}]}}
                """;

        ScanAllCommand command = McpObjectMapper.INSTANCE.readValue(json, ScanAllCommand.class);

        assertThat(command.identities()).isEqualTo(aliceAndBob());
        assertThat(new ScanAllCommand("http://target/mcp", null, null, null, null, null, false, null).identities())
                .isEqualTo(CommandIdentities.NONE);
    }

    private static CommandIdentities aliceAndBob() {
        return new CommandIdentities(new CommandUser("alice", null, null, "ALICE_ONLY", Map.of("id", "a-1")),
                List.of(new CommandUser("bob", IdentityRole.PEER, new CommandAuth(null, Map.of("X-Api-Key", "bob-key")),
                        "BOB_ONLY", Map.of("id", "b-1"))),
                Set.of("get_campaign"), List.of(new ExpectedAccess(LIST_TARGETS, AccessExpectation.SHARED_BY_DESIGN)),
                List.of(getCampaignSeed()));
    }

    private static SeedCall getCampaignSeed() {
        ObjectNode params = McpObjectMapper.INSTANCE.createObjectNode().put("name", "get_campaign");
        params.putObject("arguments").put("id", "a-1").put("limit", 2);
        return new SeedCall("tools/call", params);
    }

    private static CommandUser user(String name, IdentityRole role, CommandAuth auth) {
        return new CommandUser(name, role, auth, null, null);
    }

    private static McpToolDefinition tool(String name) {
        return new McpToolDefinition(name, "", "{\"type\":\"object\"}");
    }
}
