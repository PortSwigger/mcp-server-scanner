package com.mcpscanner;

import com.mcpscanner.testutil.InMemoryPreferences;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.access.mining.MiningListener;
import com.mcpscanner.access.mining.MiningReply;
import com.mcpscanner.access.mining.MiningReport;
import com.mcpscanner.access.mining.WriteCallApproval;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.registry.CheckInstrumentation;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.PrimaryConnection;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.identity.discovery.IdentityListings;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.scan.OwnedArguments;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.scan.request.McpMessage;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.scan.request.RequestGenerator;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MiningWiringTest {

    private static final McpToolDefinition LIST_DOCUMENTS = readOnly("list_documents",
            "{\"type\":\"object\",\"properties\":{}}");
    private static final McpToolDefinition GET_DOCUMENT = readOnly("get_document",
            "{\"type\":\"object\",\"properties\":{\"doc_id\":{\"type\":\"string\"}},\"required\":[\"doc_id\"]}");

    private static final McpToolDefinition DELETE_DOCUMENT = new McpToolDefinition("delete_document", "",
            "{\"type\":\"object\",\"properties\":{\"doc_id\":{\"type\":\"string\"}},\"required\":[\"doc_id\"]}");

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
    private ExtensionFoundation foundation;
    private ScanningWiring scanning;
    private MiningWiring mining;
    private final ConnectedInventory inventory = new ConnectedInventory();

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        PersistedObject savedSettings = InMemoryPersistedObject.create();
        when(api.persistence().extensionData()).thenReturn(savedSettings);
        when(api.persistence().preferences()).thenReturn(new InMemoryPreferences());
        foundation = ExtensionFoundation.create(api);
        ConnectionWiring connection = ConnectionWiring.create(api, foundation);
        AccessWiring access = AccessWiring.create(foundation, connection, new IdentityListings());
        scanning = ScanningWiring.create(api, foundation, connection,
                RequestBuildingWiring.create(foundation, connection, access.authHolder()), access,
                ScanFoundation.create(api, foundation, connection),
                CheckInstrumentation.NONE, java.util.function.UnaryOperator.identity(),
                com.mcpscanner.checks.api.SignedInConsent.OPTED_OUT);
        mining = MiningWiring.withSender(foundation, access, inventory, (identity, call) ->
                MiningReply.of(200, structured(Principal.PRIMARY_ID.equals(identity.id())
                        ? "{\"documents\":[{\"doc_id\":\"d-alice-0001\"}]}" : "{}")));
        inventory.connected(new PrimaryConnection("https://mcp.test/mcp", TransportType.STREAMABLE_HTTP,
                new ConnectResult(List.of(LIST_DOCUMENTS, GET_DOCUMENT), List.of(), List.of(), List.of(),
                        ServerMetadata.empty())));
    }

    @Test
    void aMinedPrivateValueReachesAGeneratedToolCall() throws Exception {
        mineToCompletion();

        assertThat(scannedDocId(GET_DOCUMENT)).isEqualTo("d-alice-0001");
    }

    @Test
    void aMinedValueNeverFillsAToolThatMayWrite() throws Exception {
        mineToCompletion();

        assertThat(scannedDocId(DELETE_DOCUMENT)).isNotEqualTo("d-alice-0001");
    }

    @Test
    void withMinedIdsInWriteToolsOnAMinedValueFillsAToolThatMayWrite() throws Exception {
        new com.mcpscanner.access.mining.MiningPreferences(foundation.configStore()).setMinedIdsInWriteTools(true);
        mineToCompletion();

        assertThat(scannedDocId(DELETE_DOCUMENT)).isEqualTo("d-alice-0001");
        assertThat(scanning.scanOwnerArguments().minedArgumentsFor(DELETE_DOCUMENT)).containsExactly("doc_id");
    }

    private void mineToCompletion() throws Exception {
        CompletableFuture<MiningReport> finished = new CompletableFuture<>();
        mining.mining().start(MiningListener.onFinished(finished::complete), WriteCallApproval.REFUSE);
        finished.get(5, TimeUnit.SECONDS);
    }

    private String scannedDocId(McpToolDefinition tool) {
        ScanInventory owned = OwnedArguments.apply(ScanInventory.toolsOnly(List.of(tool)),
                scanning.scanOwnerArguments());
        McpMessage call = (McpMessage) RequestGenerator.standard().scanThisRequest(RequestFamily.TOOLS_CALL, owned)
                .messages().get(0);
        return call.params().orElseThrow().path("arguments").path("doc_id").asText();
    }

    @Test
    void disconnectForgetsTheInventorySoMiningCannotStart() {
        mining.sessionResets().forEach(Runnable::run);

        assertThat(mining.mining().blocker()).isPresent();
        assertThat(mining.mining().minedForCurrentIdentities()).isFalse();
    }

    private static McpToolDefinition readOnly(String name, String schema) {
        return new McpToolDefinition(name, "", schema, List.of(), new ToolAnnotations(null, true, null, null, null));
    }

    private static ObjectNode structured(String json) {
        try {
            ObjectNode result = McpObjectMapper.INSTANCE.createObjectNode();
            result.set("structuredContent", McpObjectMapper.INSTANCE.readTree(json));
            return result;
        } catch (Exception unreadable) {
            throw new IllegalStateException(unreadable);
        }
    }
}
