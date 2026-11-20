package com.mcpscanner.access;

import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.checks.api.crossidentity.SyntheticPrincipals;
import com.mcpscanner.identity.discovery.DiscoveryOutcome;
import com.mcpscanner.identity.discovery.IdentityListing;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ToolAnnotations;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public final class AccessFixtures {

    public static final Principal ALICE = new Principal(Principal.PRIMARY_ID, Principal.PRIMARY_NAME, PrincipalRole.PRIMARY,
            () -> Map.of("Authorization", "Bearer alice-token"), Optional.empty(), Map.of());
    public static final Principal BOB = identity("bob", PrincipalRole.PEER);
    public static final Principal CAROL = identity("carol", PrincipalRole.LOWER);
    public static final Principal DAVE = identity("dave", PrincipalRole.HIGHER);
    private static final List<Principal> SYNTHETIC = new SyntheticPrincipals(NoAuthStrategy::new).all();

    private final List<Principal> compared = new ArrayList<>();
    private Principal primary = ALICE;
    private final Map<String, DiscoveryOutcome> outcomes = new ConcurrentHashMap<>();
    private final InMemoryExpectations expectations = new InMemoryExpectations();

    public static Principal identity(String name, PrincipalRole role) {
        return new Principal(name, name, role, () -> Map.of("Authorization", "Bearer " + name + "-token"),
                Optional.empty(), Map.of());
    }

    public static McpToolDefinition tool(String name) {
        return new McpToolDefinition(name, name, "{\"type\":\"object\",\"properties\":{}}");
    }

    public static McpToolDefinition readOnlyTool(String name) {
        return new McpToolDefinition(name, name, "{\"type\":\"object\",\"properties\":{}}", List.of(),
                new ToolAnnotations(null, true, null, null, null));
    }

    public static McpResourceDefinition resource(String uri) {
        return new McpResourceDefinition(uri, uri, "", "text/plain");
    }

    public static AccessItemKey toolKey(String name) {
        return new AccessItemKey(AccessItemKey.Kind.TOOL, name);
    }

    public static AccessItemKey resourceKey(String uri) {
        return new AccessItemKey(AccessItemKey.Kind.RESOURCE, uri);
    }

    public static IdentityListing listing(List<McpToolDefinition> tools, List<McpResourceDefinition> resources) {
        Map<String, McpToolDefinition> toolMap = new LinkedHashMap<>();
        tools.forEach(tool -> toolMap.put(tool.name(), tool));
        Map<String, McpResourceDefinition> resourceMap = new LinkedHashMap<>();
        resources.forEach(resource -> resourceMap.put(resource.uri(), resource));
        return new IdentityListing(toolMap, resourceMap, java.util.Set.of("notes://{id}"), java.util.Set.of("greet"));
    }

    public AccessFixtures withPrimary(Principal value) {
        primary = value;
        return this;
    }

    public AccessFixtures compare(Principal... principals) {
        compared.addAll(List.of(principals));
        return this;
    }

    public AccessFixtures lists(Principal principal, List<McpToolDefinition> tools, List<McpResourceDefinition> resources) {
        outcomes.put(principal.id(), new DiscoveryOutcome.Listed(listing(tools, resources)));
        return this;
    }

    public AccessFixtures discovering(Principal principal) {
        outcomes.put(principal.id(), DiscoveryOutcome.Discovering.INSTANCE);
        return this;
    }

    public PrincipalRoster roster() {
        return PrincipalRoster.of(primary, compared);
    }

    public InMemoryExpectations expectations() {
        return expectations;
    }

    public AccessMatrix matrix() {
        return matrix(expectations);
    }

    public AccessMatrix matrix(AccessExpectations stored) {
        return new AccessMatrix(this::roster, () -> Map.copyOf(outcomes), stored, SYNTHETIC);
    }

    public AccessMatrix matrix(List<Principal> synthetic) {
        return new AccessMatrix(this::roster, () -> Map.copyOf(outcomes), expectations, synthetic);
    }

    public static final class InMemoryExpectations implements AccessExpectations {
        private final Map<AccessItemKey, AccessExpectation> stored = new HashMap<>();

        @Override
        public Optional<AccessExpectation> stored(AccessItemKey item) {
            return Optional.ofNullable(stored.get(item));
        }

        @Override
        public void store(AccessItemKey item, AccessExpectation expectation) {
            stored.put(item, expectation);
        }
    }
}
