package com.mcpscanner.access;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.access.mining.MinedValueRule;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.OwnedObjects;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.scan.ScanTarget;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class OwnerRequestsTest {

    private static final String SCHEMA = "{\"type\":\"object\",\"properties\":{\"invoice_id\":{\"type\":\"string\"}}}";
    private static final Principal OWNER = new Principal(Principal.PRIMARY_ID, "alice", PrincipalRole.PRIMARY,
            Map::of, Optional.empty(), new OwnedObjects(Map.of(), Map.of("invoice_id", "inv-alice-1")), Map::of);

    private static final McpToolDefinition DELETE_INVOICE = new McpToolDefinition("delete_invoice", "", SCHEMA);

    private final List<ScanTarget> rendered = new ArrayList<>();
    private final AtomicBoolean minedInWriteTools = new AtomicBoolean();
    private final OwnerRequests requests = new OwnerRequests(target -> {
        rendered.add(target);
        return mock(HttpRequest.class);
    }, mock(IdentityRequests.class), new MinedValueRule(minedInWriteTools::get));

    @Test
    void aReadToolCarriesTheOwnersMinedValue() throws Exception {
        requests.forOwner(row(new McpToolDefinition("get_invoice", "", SCHEMA, List.of(),
                new ToolAnnotations(null, true, null, null, null))));

        assertThat(invoiceDefault()).isEqualTo("inv-alice-1");
    }

    @Test
    void aWriteToolKeepsItsSchemaDefault() throws Exception {
        requests.forOwner(row(DELETE_INVOICE));

        assertThat(invoiceDefault()).isNull();
        assertThat(requests.minedArguments(List.of(row(DELETE_INVOICE))).present()).isFalse();
    }

    @Test
    void withMinedIdsInWriteToolsOnAWriteToolCarriesTheOwnersMinedValueAndSaysSo() throws Exception {
        minedInWriteTools.set(true);

        requests.forOwner(row(DELETE_INVOICE));

        assertThat(invoiceDefault()).isEqualTo("inv-alice-1");
        assertThat(requests.minedArguments(List.of(row(DELETE_INVOICE))).of(DELETE_INVOICE))
                .containsExactly("invoice_id");
    }

    @Test
    void aPairRequestBindsTheOtherUserOnceToTheItemsRenderedRequestWithoutBindingTheOwner() {
        IdentityRequests identities = mock(IdentityRequests.class);
        HttpRequest rendered = mock(HttpRequest.class);
        Principal bob = new Principal("bob", "bob", PrincipalRole.PEER, Map::of, Optional.empty(), Map.of());

        new OwnerRequests(target -> rendered, identities, new MinedValueRule(() -> false)).as(row(DELETE_INVOICE), bob);

        verify(identities).as(bob, rendered);
        verify(identities, never()).routed(any(), any());
    }

    @Test
    void anOwnersCallCarriesOnlyRequiredArgumentsAndTheOwnedOnes() throws Exception {
        String schema = "{\"type\":\"object\",\"properties\":{\"invoice_id\":{\"type\":\"string\"},"
                + "\"where\":{\"type\":\"string\"}},\"required\":[]}";

        requests.forOwner(row(new McpToolDefinition("get_invoice", "", schema, List.of(),
                new ToolAnnotations(null, true, null, null, null))));

        ScanTarget.Tool target = (ScanTarget.Tool) rendered.get(0);
        assertThat(McpObjectMapper.INSTANCE.readTree(target.tool().inputSchema()).path("properties").fieldNames())
                .toIterable().containsExactly("invoice_id");
    }

    private String invoiceDefault() throws Exception {
        ScanTarget.Tool target = (ScanTarget.Tool) rendered.get(0);
        JsonNode schema = McpObjectMapper.INSTANCE.readTree(target.tool().inputSchema());
        JsonNode value = schema.path("properties").path("invoice_id").get("default");
        return value == null ? null : value.asText();
    }

    private static AccessRow row(McpToolDefinition tool) {
        return new AccessRow(AccessItem.tool(tool), OWNER, AccessExpectation.ANY_SIGNED_IN, true, Map.of(),
                AccessCell.of(ListingState.NO_LISTING, Optional.empty(), false));
    }
}
