package com.mcpscanner.scan;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.field.MetaEnvelopeRegistry;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.scan.request.ScanMessage;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

class MetaEnvelopeCarriersTest {

    private static final String SERVER_A = "a.example";
    private static final String SERVER_B = "b.example";

    private final MetaEnvelopeRegistry registry = new MetaEnvelopeRegistry();
    private final AtomicBoolean everyRequest = new AtomicBoolean(false);
    private final McpEventLog eventLog = new McpEventLog(null);
    private final MetaEnvelopeCarriers carriers = new MetaEnvelopeCarriers(registry, everyRequest::get, eventLog);
    private final List<ScanMessage> messages = new ArrayList<>();
    private final List<HttpRequest> requests = new ArrayList<>();

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void aScanOfManyToolCallsOnOneServerFuzzesTheEnvelopeOfExactlyOne() {
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(1));
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(2));
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(3));

        carriers.hold(messages, requests);

        assertThat(fuzzed()).containsExactly(true, false, false);
    }

    @Test
    void aCheapListingRequestIsPreferredAsTheCarrierOverAnEarlierToolCall() {
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(1));
        add(RequestFamily.TOOLS_LIST, SERVER_A, list(2));
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(3));

        carriers.hold(messages, requests);

        assertThat(fuzzed()).containsExactly(false, true, false);
    }

    @Test
    void aNotificationIsNeverTheCarrierWhileARequestThatGetsAReplyCarriesTheEnvelope() {
        add(RequestFamily.NOTIFICATION_CANCELLED, SERVER_A, notification());
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(2));
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(3));

        carriers.hold(messages, requests);

        assertThat(fuzzed()).containsExactly(false, true, false);
    }

    @Test
    void aNotificationCarriesTheEnvelopeWhenNoRequestCarriesOne() {
        add(RequestFamily.NOTIFICATION_CANCELLED, SERVER_A, notification());
        add(RequestFamily.TOOLS_LIST, SERVER_A, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}");

        carriers.hold(messages, requests);

        assertThat(fuzzed().get(0)).isTrue();
    }

    @Test
    void aRequestWithNoEnvelopeIsNeverChosenAsTheCarrier() {
        add(RequestFamily.TOOLS_LIST, SERVER_A, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(2));
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(3));

        carriers.hold(messages, requests);

        assertThat(fuzzed().subList(1, 3)).containsExactly(true, false);
    }

    @Test
    void twoServersInOneScanGetOneCarrierEach() {
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(1));
        add(RequestFamily.TOOLS_CALL, SERVER_B, call(2));
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(3));
        add(RequestFamily.TOOLS_CALL, SERVER_B, call(4));

        carriers.hold(messages, requests);

        assertThat(fuzzed()).containsExactly(true, true, false, false);
    }

    @Test
    void anotherPathOnTheSameHostIsAnotherServer() {
        add(RequestFamily.TOOLS_CALL, SERVER_A, "/one", call(1));
        add(RequestFamily.TOOLS_CALL, SERVER_A, "/two?x=1", call(2));
        add(RequestFamily.TOOLS_CALL, SERVER_A, "/one", call(3));

        carriers.hold(messages, requests);

        assertThat(fuzzed()).containsExactly(true, true, false);
    }

    @Test
    void aProbeCallIsNeitherCarrierNorPassenger() {
        messages.add(message(RequestFamily.TOOLS_CALL, Optional.of(ArgumentPath.of("a"))));
        requests.add(request(SERVER_A, "/mcp", call(1)));
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(2));
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(3));

        carriers.hold(messages, requests);

        assertThat(fuzzed()).containsExactly(true, true, false);
    }

    @Test
    void theScansEndReleasesItsHolds() {
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(1));
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(2));

        Runnable release = carriers.hold(messages, requests);
        release.run();

        assertThat(fuzzed()).containsExactly(true, true);
    }

    @Test
    void twoOverlappingScansKeepEachOthersHolds() {
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(1));
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(2));
        Runnable first = carriers.hold(messages, requests);
        Runnable second = carriers.hold(messages, requests);

        first.run();
        assertThat(fuzzed()).containsExactly(true, false);

        second.run();
        assertThat(fuzzed()).containsExactly(true, true);
    }

    @Test
    void aBodyCarriedByOneScanIsFuzzedWhileAnotherScanHoldsItAsAPassenger() {
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(1));
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(2));
        carriers.hold(messages, requests);

        carriers.hold(List.of(messages.get(1)), List.of(requests.get(1)));

        assertThat(fuzzed()).containsExactly(true, true);
    }

    @Test
    void withTheSettingOnEveryRequestHasItsEnvelopeFuzzed() {
        everyRequest.set(true);
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(1));
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(2));

        carriers.hold(messages, requests);

        assertThat(fuzzed()).containsExactly(true, true);
    }

    @Test
    void logsOncePerServerWhichRequestCarriesTheEnvelope() {
        add(RequestFamily.TOOLS_CALL, SERVER_A, call(1));
        add(RequestFamily.TOOLS_LIST, SERVER_A, list(2));
        add(RequestFamily.TOOLS_CALL, SERVER_B, call(3));

        carriers.hold(messages, requests);

        assertThat(eventLog.snapshot()).extracting(McpEventLog.LogEntry::message).containsExactly(
                "Request metadata (_meta) is fuzzed once for http://a.example:80/mcp, on TOOLS_LIST subject",
                "Request metadata (_meta) is fuzzed once for http://b.example:80/mcp, on TOOLS_CALL subject");
    }

    private List<Boolean> fuzzed() {
        return requests.stream().map(request -> registry.fuzzesEnvelopeOf(request.bodyToString())).toList();
    }

    private void add(RequestFamily family, String host, String body) {
        add(family, host, "/mcp", body);
    }

    private void add(RequestFamily family, String host, String path, String body) {
        messages.add(message(family, Optional.empty()));
        requests.add(request(host, path, body));
    }

    private static ScanMessage message(RequestFamily family, Optional<ArgumentPath> added) {
        ScanMessage message = mock(ScanMessage.class);
        lenient().when(message.family()).thenReturn(family);
        lenient().when(message.subject()).thenReturn(family.name() + " subject");
        lenient().when(message.addedArgument()).thenReturn(added);
        return message;
    }

    private static HttpRequest request(String host, String path, String body) {
        HttpService service = HttpService.httpService(host, 80, false);
        ByteArray bytes = ByteArray.byteArray(body.getBytes(StandardCharsets.UTF_8));
        HttpRequest request = mock(HttpRequest.class);
        lenient().when(request.httpService()).thenReturn(service);
        lenient().when(request.path()).thenReturn(path);
        lenient().when(request.bodyToString()).thenReturn(body);
        lenient().when(request.body()).thenReturn(bytes);
        return request;
    }

    private static String call(int id) {
        return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"method\":\"tools/call\",\"params\":{\"name\":\"t" + id
                + "\",\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}}}";
    }

    private static String notification() {
        return "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":"
                + "{\"requestId\":1,\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}}}";
    }

    private static String list(int id) {
        return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"method\":\"tools/list\",\"params\":"
                + "{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}}}";
    }
}
