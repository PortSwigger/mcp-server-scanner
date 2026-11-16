package com.mcpscanner.checks.registry;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.api.RecordingChecks;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class StreamedAuditTest {

    private static final String URL = "https://mcp.example.test/mcp";
    private static final String TOOL_CALL = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\","
            + "\"params\":{\"name\":\"ping_host\",\"arguments\":{\"host\":\"a\"}}}";

    private final McpEventLog eventLog = new McpEventLog(null);
    private final Http http = mock(Http.class);
    private final AuditInsertionPoint point = mock(AuditInsertionPoint.class);
    private final HttpRequestResponse streamedBase =
            AdapterFixtures.streamedBaseFor(ImmutableHttpRequest.post(URL, Map.of(), TOOL_CALL));

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    void aBaseWithoutAReplyRunsTheCheckWithProbesGoingThroughTheGivenHttp(Kind kind) {
        RecordingChecks.Recording check = kind.check();

        kind.adapt(AdapterFixtures.settingsAllowing(true), eventLog, check).doCheck(streamedBase, point, http);
        HttpRequest probe = HttpRequest.httpRequestFromUrl(URL);
        check.calls.get(0).http().sendRequest(probe);

        assertThat(check.calls).singleElement().extracting(RecordingChecks.Call::base).isSameAs(streamedBase);
        verify(http).sendRequest(org.mockito.ArgumentMatchers.any(HttpRequest.class));
        assertThat(infos()).contains("Scan check: streamed — started");
        assertThat(infos()).anyMatch(line -> line.contains("without its reply"));
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    void aBaseWithAReplySaysNothingAboutAMissingReply(Kind kind) {
        HttpRequestResponse replied = AdapterFixtures.baseOn("mcp.example.test");
        HttpRequest request = streamedBase.request();
        burp.api.montoya.http.message.responses.HttpResponse reply =
                mock(burp.api.montoya.http.message.responses.HttpResponse.class);
        when(replied.request()).thenReturn(request);
        when(replied.response()).thenReturn(reply);

        kind.adapt(AdapterFixtures.settingsAllowing(true), eventLog, kind.check()).doCheck(replied, point, http);

        assertThat(infos()).noneMatch(line -> line.contains("without its reply"));
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    void aBaseWithoutAReplySaysOnceThatTheCheckRunsWithoutBurpsReply(Kind kind) {
        McpCheckAdapter<?> adapter = kind.adapt(AdapterFixtures.settingsAllowing(true), eventLog, kind.check());

        adapter.doCheck(streamedBase, point, http);
        adapter.doCheck(streamedBase, point, http);

        assertThat(infos()).containsOnlyOnce("Scan check: streamed — auditing tools/call ping_host at "
                + streamedBase.request().url() + " without its reply (Burp gave the extension no reply: it withholds streamed replies,"
                + " and a timeout or dropped connection looks the same)");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    void aBaseWhoseRequestThrowsBeforeTheCheckStartsIsLoggedAndRethrown(Kind kind) {
        IllegalStateException withheld = new IllegalStateException("request withheld");
        HttpRequestResponse unreadable = AdapterFixtures.baseOn("mcp.example.test");
        when(unreadable.request()).thenThrow(withheld);
        McpCheckAdapter<?> adapter = kind.adapt(AdapterFixtures.settingsAllowing(true), eventLog,
                kind.check().requiringReply());

        assertThatThrownBy(() -> adapter.doCheck(unreadable, point, http)).isSameAs(withheld);
        assertThat(errors()).containsExactly("Scan check: streamed — threw IllegalStateException: request withheld");
    }

    @ParameterizedTest
    @EnumSource(Kind.class)
    void aSettingsFailureBeforeTheCheckStartsIsLoggedAndRethrown(Kind kind) {
        IllegalStateException unreadable = new IllegalStateException("settings unreadable");
        ScanCheckSettings settings = mock(ScanCheckSettings.class);
        when(settings.isEnabled(anyString(), anyBoolean())).thenThrow(unreadable);
        McpCheckAdapter<?> adapter = kind.adapt(settings, eventLog, kind.check());

        assertThatThrownBy(() -> adapter.doCheck(streamedBase, point, http)).isSameAs(unreadable);
        assertThat(errors()).containsExactly("Scan check: streamed — threw IllegalStateException: settings unreadable");
    }

    private List<String> infos() {
        return messagesAt(McpEventLog.Level.INFO);
    }

    private List<String> errors() {
        return messagesAt(McpEventLog.Level.ERROR);
    }

    private List<String> messagesAt(McpEventLog.Level level) {
        return eventLog.snapshot().stream().filter(entry -> entry.level() == level)
                .map(McpEventLog.LogEntry::message).toList();
    }

    enum Kind {
        REQUEST {
            @Override
            RecordingChecks.Recording check() {
                return new RecordingChecks.Request("streamed", List.of());
            }

            @Override
            McpCheckAdapter<?> adapt(ScanCheckSettings settings, McpEventLog eventLog, RecordingChecks.Recording check) {
                return new RequestCheckAdapter(settings, eventLog, (RecordingChecks.Request) check);
            }
        },
        INSERTION_POINT {
            @Override
            RecordingChecks.Recording check() {
                return new RecordingChecks.InsertionPoint("streamed", List.of());
            }

            @Override
            McpCheckAdapter<?> adapt(ScanCheckSettings settings, McpEventLog eventLog, RecordingChecks.Recording check) {
                return new InsertionPointCheckAdapter(settings, eventLog, (RecordingChecks.InsertionPoint) check);
            }
        },
        HOST {
            @Override
            RecordingChecks.Recording check() {
                return new RecordingChecks.Host("streamed", List.of());
            }

            @Override
            McpCheckAdapter<?> adapt(ScanCheckSettings settings, McpEventLog eventLog, RecordingChecks.Recording check) {
                return new HostCheckAdapter(settings, eventLog, (RecordingChecks.Host) check);
            }
        };

        abstract RecordingChecks.Recording check();

        abstract McpCheckAdapter<?> adapt(ScanCheckSettings settings, McpEventLog eventLog,
                                          RecordingChecks.Recording check);
    }
}
