package com.mcpscanner.ui.access;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.access.mining.AccessMining;
import com.mcpscanner.access.mining.MiningInputs;
import com.mcpscanner.access.mining.MiningPreferences;
import com.mcpscanner.access.mining.MiningReply;
import com.mcpscanner.access.mining.MiningSender;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.identity.EnteredValue;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.IdentityRosterSource;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.identity.RegistryOwnedValues;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.testutil.InMemoryPersistedObject;

import java.awt.Component;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Optional;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.Mockito.mock;

final class MiningUiFixture implements AutoCloseable {

    static final McpToolDefinition LIST_DOCUMENTS = readOnly("list_documents", "{\"type\":\"object\",\"properties\":{}}");
    static final McpToolDefinition GET_DOCUMENT = readOnly("get_document",
            "{\"type\":\"object\",\"properties\":{\"doc_id\":{\"type\":\"string\"}}}");
    static final McpToolDefinition ARCHIVE_DOCUMENT = new McpToolDefinition("archive_document", "",
            "{\"type\":\"object\",\"properties\":{\"doc_id\":{\"type\":\"string\"}}}");

    final ExtensionConfigStore config = InMemoryPersistedObject.configStore();
    final IdentityRegistry registry = new IdentityRegistry(new IdentityStore(config, mock(McpEventLog.class)));
    final RegistryOwnedValues store = new RegistryOwnedValues(registry);
    final FakeDialogs dialogs = new FakeDialogs();
    final AtomicReference<MiningSender> sender = new AtomicReference<>(MiningUiFixture::documents);
    final AtomicReference<Optional<ScanInventory>> inventory = new AtomicReference<>(Optional.of(
            ScanInventory.toolsOnly(List.of(LIST_DOCUMENTS, GET_DOCUMENT, ARCHIVE_DOCUMENT))));
    final Identity alice;
    final Identity bob;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    final AccessMining mining;

    MiningUiFixture() {
        alice = registry.primaryUser().withName("alice");
        registry.update(alice);
        bob = registry.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER).withCompared(true));
        registry.setCredential(bob.id(), new BearerTokenAuthStrategy("bob-token"));
        mining = new AccessMining(new MiningInputs(inventory::get,
                new IdentityRosterSource(() -> new BearerTokenAuthStrategy("alice-token"), registry),
                () -> registry.primaryUser().id()), (identity, call) -> sender.get().send(identity, call),
                new MiningPreferences(config), store, worker, () -> Runnable::run,
                McpEventLog.noop());
    }

    MiningServices services() {
        return new MiningServices(mining, store, registry::identities, dialogs);
    }

    static MiningReply documents(Principal identity, com.mcpscanner.access.mining.MiningCall call) {
        String own = Principal.PRIMARY_ID.equals(identity.id()) ? "d-alice-0001"
                : identity.name().equals("bob") ? "d-bob-0042" : null;
        return MiningReply.of(200, structured(own == null ? "{}" : "{\"documents\":[{\"doc_id\":\"" + own + "\"}]}"));
    }

    static ObjectNode structured(String json) {
        try {
            ObjectNode result = McpObjectMapper.INSTANCE.createObjectNode();
            result.set("structuredContent", McpObjectMapper.INSTANCE.readTree(json));
            return result;
        } catch (Exception unreadable) {
            throw new IllegalStateException(unreadable);
        }
    }

    private static McpToolDefinition readOnly(String name, String schema) {
        return new McpToolDefinition(name, "", schema, List.of(), new ToolAnnotations(null, true, null, null, null));
    }

    @Override
    public void close() {
        mining.cancel();
        worker.shutdownNow();
    }

    static final class FakeDialogs implements MiningDialogs {
        final Queue<MineFirstChoice> mineFirstAnswers = new ArrayDeque<>();
        final Queue<Boolean> confirmAnswers = new ArrayDeque<>();
        final Queue<ClearChoice> clearAnswers = new ArrayDeque<>();
        final Queue<Optional<EnteredValue>> enteredAnswers = new ArrayDeque<>();
        final Queue<Optional<Set<String>>> toolAnswers = new ArrayDeque<>();
        final List<String> asked = new CopyOnWriteArrayList<>();
        final List<List<String>> offeredTools = new CopyOnWriteArrayList<>();
        final List<ToolsToCall> confirmedTools = new CopyOnWriteArrayList<>();
        final List<ToolsToCall> mineFirstTools = new CopyOnWriteArrayList<>();

        @Override
        public MineFirstChoice mineFirst(Component parent, ToolsToCall tools) {
            asked.add("mine-first");
            mineFirstTools.add(tools);
            return Optional.ofNullable(mineFirstAnswers.poll()).orElse(MineFirstChoice.CANCEL);
        }

        @Override
        public boolean confirmMining(Component parent, ToolsToCall tools) {
            asked.add("confirm-mining");
            confirmedTools.add(tools);
            return Optional.ofNullable(confirmAnswers.poll()).orElse(true);
        }

        @Override
        public ClearChoice clearMined(Component parent, String userName) {
            asked.add("clear " + userName);
            return Optional.ofNullable(clearAnswers.poll()).orElse(ClearChoice.CANCEL);
        }

        @Override
        public Optional<EnteredValue> enterValue(Component parent, Optional<EnteredValue> current) {
            asked.add("enter " + current.map(EnteredValue::value).orElse("new"));
            return Optional.ofNullable(enteredAnswers.poll()).flatMap(answer -> answer);
        }

        @Override
        public Optional<Set<String>> chooseWriteTools(Component parent, List<McpToolDefinition> tools,
                                                      Set<String> selected) {
            offeredTools.add(tools.stream().map(McpToolDefinition::name).toList());
            return Optional.ofNullable(toolAnswers.poll()).flatMap(answer -> answer);
        }
    }
}
