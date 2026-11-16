package com.mcpscanner.automation;

import com.mcpscanner.access.WriteReplayConfirmations;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.OwnedValues;
import com.mcpscanner.mcp.McpToolDefinition;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

public final class IdentityHandover {

    private final IdentityRegistry registry;
    private final WriteReplayConfirmations confirmations;
    private final BiConsumer<AccessItemKey, AccessExpectation> expectations;
    private final Consumer<List<SeedCall>> itemSeeds;

    public IdentityHandover(IdentityRegistry registry, WriteReplayConfirmations confirmations,
                            BiConsumer<AccessItemKey, AccessExpectation> expectations,
                            Consumer<List<SeedCall>> itemSeeds) {
        this.registry = registry;
        this.confirmations = confirmations;
        this.expectations = expectations;
        this.itemSeeds = itemSeeds;
    }

    void beforeConnect(CommandIdentities identities, CommandAuth connectAsAuth) {
        registry.otherUsers().forEach(other -> registry.remove(other.id()));
        identities.primaryUser().ifPresent(user -> becomeConnectAs(user, connectAsAuth));
        identities.others().forEach(this::addCompared);
    }

    void afterConnect(CommandIdentities identities, List<McpToolDefinition> tools) {
        confirmations.confirm(listed(identities.confirmedWrites(), tools));
        identities.expectations().forEach(expected -> expectations.accept(expected.item(), expected.expectation()));
        itemSeeds.accept(identities.itemSeeds());
    }

    private void becomeConnectAs(CommandUser user, CommandAuth auth) {
        Identity connectAs = described(registry.primaryUser(), user, auth);
        registry.update(connectAs);
        registry.setCredential(connectAs.id(), auth.strategy());
    }

    private void addCompared(CommandUser user) {
        Identity added = registry.add(described(Identity.create(user.name(), user.role(), user.auth().kind()), user,
                user.auth()));
        registry.setCredential(added.id(), user.auth().strategy());
    }

    private static Identity described(Identity identity, CommandUser user, CommandAuth auth) {
        return identity.withName(user.name())
                .withAuthKind(auth.kind())
                .withPrivateMarker(user.privateMarker())
                .withOwnedValues(OwnedValues.entered(user.ownedObjects()))
                .withHeaderNames(auth.kind() == IdentityAuthKind.CUSTOM_HEADERS ? List.copyOf(auth.headers().keySet())
                        : List.of());
    }

    private static List<McpToolDefinition> listed(Set<String> names, List<McpToolDefinition> tools) {
        Set<String> unlisted = new HashSet<>(names);
        tools.forEach(tool -> unlisted.remove(tool.name()));
        if (!unlisted.isEmpty()) {
            throw new IllegalArgumentException("The server lists no tools named " + unlisted);
        }
        return tools.stream().filter(tool -> names.contains(tool.name())).toList();
    }
}
