package com.mcpscanner;

import com.mcpscanner.testutil.InMemoryPreferences;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;
import com.mcpscanner.mcp.BurpNativeJsonRpcFields;
import com.mcpscanner.scan.field.MetaEnvelopeRegistry;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RawHttpRequestStub;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScanFieldWiringTest {

    private static final String TOOL_CALL = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"fetch\",\"arguments\":{\"url\":\"http://a\"},\"_meta\":{\"k\":\"v\"}}}";
    private static final List<String> EVERY_FIELD = List.of(
            "MCP field: params.name", "MCP field: params.arguments.url", "MCP field: params._meta.k");

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        PersistedObject savedSettings = InMemoryPersistedObject.create();
        when(api.persistence().extensionData()).thenReturn(savedSettings);
        when(api.persistence().preferences()).thenReturn(new InMemoryPreferences());
    }

    @Test
    void burpWithNativeJsonRpcFieldsGetsOnlyTheFieldsItLeavesUnfuzzed() {
        when(api.burpSuite().version().buildNumber()).thenReturn(BurpNativeJsonRpcFields.FIRST_NATIVE_BUILD);

        ScanFieldWiring fields = ScanFieldWiring.create(api, ExtensionFoundation.create(api));

        assertThat(names(registeredProvider())).containsExactly("MCP field: params.name", "MCP field: params._meta.k");
        assertThat(names(fields.everyField())).containsExactlyElementsOf(EVERY_FIELD);
    }

    @Test
    void olderBurpGetsEveryField() {
        when(api.burpSuite().version().buildNumber()).thenReturn(BurpNativeJsonRpcFields.FIRST_NATIVE_BUILD - 1);

        ScanFieldWiring fields = ScanFieldWiring.create(api, ExtensionFoundation.create(api));

        assertThat(names(registeredProvider())).containsExactlyElementsOf(EVERY_FIELD);
        assertThat(names(fields.everyField())).containsExactlyElementsOf(EVERY_FIELD);
    }

    @Test
    void aBurpWhoseVersionCannotBeReadGetsEveryField() {
        when(api.burpSuite()).thenThrow(new IllegalStateException("version unavailable"));

        ScanFieldWiring.create(api, ExtensionFoundation.create(api));

        assertThat(names(registeredProvider())).containsExactlyElementsOf(EVERY_FIELD);
    }

    @Test
    void theBurpAuditAndEngineProvidersBothLeaveAScansPassengerEnvelopeAlone() {
        when(api.burpSuite().version().buildNumber()).thenReturn(BurpNativeJsonRpcFields.FIRST_NATIVE_BUILD - 1);
        ScanFieldWiring fields = ScanFieldWiring.create(api, ExtensionFoundation.create(api));

        fields.metaEnvelopes().hold(TOOL_CALL, MetaEnvelopeRegistry.Role.PASSENGER);

        List<String> withoutEnvelope = List.of("MCP field: params.name", "MCP field: params.arguments.url");
        assertThat(names(registeredProvider())).containsExactlyElementsOf(withoutEnvelope);
        assertThat(names(fields.everyField())).containsExactlyElementsOf(withoutEnvelope);
    }

    private AuditInsertionPointProvider registeredProvider() {
        ArgumentCaptor<AuditInsertionPointProvider> provider = ArgumentCaptor.forClass(AuditInsertionPointProvider.class);
        verify(api.scanner()).registerInsertionPointProvider(provider.capture());
        return provider.getValue();
    }

    private static List<String> names(AuditInsertionPointProvider provider) {
        HttpRequest request = RawHttpRequestStub.post(TOOL_CALL, Map.of("Content-Type", "application/json"));
        HttpRequestResponse base = mock(HttpRequestResponse.class);
        when(base.request()).thenReturn(request);
        return provider.provideInsertionPoints(base).stream().map(AuditInsertionPoint::name).toList();
    }
}
