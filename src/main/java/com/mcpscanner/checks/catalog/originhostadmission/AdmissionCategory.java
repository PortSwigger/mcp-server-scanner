package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.mcpscanner.checks.shared.stream.StreamEvidenceNote;

enum AdmissionCategory {

    ORIGIN("MCP Origin header admission", AuditIssueConfidence.FIRM, Wording.REPLAYED_RESULT,
            "Each probe changed only the Origin header; the captured Host was kept. A cross-site page can only "
                    + "send this JSON request if the server also approves a CORS preflight; the scanner reports "
                    + "that separately as a cross-origin read allowed by CORS.",
            Wording.REPLAY_EVIDENCE),
    HOST("MCP Host header admission", AuditIssueConfidence.TENTATIVE, Wording.REPLAYED_RESULT,
            "The probe changed only the Host header; any captured Origin was kept. Browsers do not send this "
                    + "header combination, and listeners behind a reverse proxy or reached by address often ignore "
                    + "Host by design. It matters for DNS rebinding only where a browser can reach this listener "
                    + "under an attacker-chosen name.",
            Wording.REPLAY_EVIDENCE),
    HOST_AND_ORIGIN("MCP Host and Origin header admission", AuditIssueConfidence.FIRM, Wording.REPLAYED_RESULT,
            "The probe sent the matching attacker Host and Origin pair a browser sends after DNS rebinding "
                    + "an attacker-controlled name to this listener.",
            Wording.REPLAY_EVIDENCE),
    STREAM_ORIGIN("MCP event stream Origin header admission", AuditIssueConfidence.FIRM,
            "The MCP server opened its server-to-client event stream under these headers:",
            "Each probe was an HTTP GET with Accept: text/event-stream in a fresh MCP session of its own, with "
                    + "only the Origin header changed. The server answered 2xx with a text/event-stream body and "
                    + "kept the stream open, as it did for a same-origin control before and after the probes. The "
                    + "event stream carries the server's notifications and requests to the client, so the "
                    + "transport's Origin validation must cover it as well as POST. The scanner could not test the "
                    + "Host header on this route.",
            StreamEvidenceNote.OPENED_OUTSIDE_BURP + " This proves header admission only: the scanner did not "
                    + "drive a browser or read events another client would receive.");

    private final String issueName;
    private final AuditIssueConfidence confidence;
    private final String lead;
    private final String probeScope;
    private final String evidenceScope;

    AdmissionCategory(String issueName, AuditIssueConfidence confidence, String lead, String probeScope,
                      String evidenceScope) {
        this.issueName = issueName;
        this.confidence = confidence;
        this.lead = lead;
        this.probeScope = probeScope;
        this.evidenceScope = evidenceScope;
    }

    String issueName() {
        return issueName;
    }

    AuditIssueConfidence confidence() {
        return confidence;
    }

    String lead() {
        return lead;
    }

    String probeScope() {
        return probeScope;
    }

    String evidenceScope() {
        return evidenceScope;
    }

    private static final class Wording {

        static final String REPLAYED_RESULT = "The MCP server returned the captured operation's result under these "
                + "headers:";
        static final String REPLAY_EVIDENCE = "The captured MCP request returned the same successful result "
                + "under the probe as in a fresh baseline and a final control. The destination, method and body "
                + "were unchanged. This proves header admission only: the scanner did not drive a browser, perform "
                + "DNS rebinding, or establish that the operation is sensitive.";

        private Wording() {
        }
    }
}
