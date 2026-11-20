package com.mcpscanner.proxy;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.client.JdkProtocolHttpTransport;
import com.mcpscanner.client.ProtocolHttpRequest;
import com.mcpscanner.client.ProtocolHttpTransport;
import com.mcpscanner.testutil.EvidenceTarget;

import java.io.InputStream;
import java.net.URI;
import java.util.List;
import java.util.Map;

public final class EvidenceProducerFixtures {

    private EvidenceProducerFixtures() {
    }

    public static List<HttpRequestResponse> recordedUpstream(URI endpoint, Map<String, String> headers)
            throws Exception {
        UpstreamCaptures captures = new UpstreamCaptures();
        ProtocolHttpTransport recording = captures.recording(new JdkProtocolHttpTransport(EvidenceTarget.jdkClient()));
        try (ForwardCapture capture = captures.open()) {
            try (InputStream body = recording.send(new ProtocolHttpRequest(endpoint, "POST", headers,
                    EvidenceTarget.TOOLS_LIST), EvidenceTarget.TIMEOUT).body()) {
                body.readAllBytes();
            }
            return capture.chosenFor(EvidenceTarget.TOOLS_LIST).orElseThrow().evidence();
        }
    }
}
