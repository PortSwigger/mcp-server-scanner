package com.mcpscanner.checks.catalog.sessionlifecycle;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.issue.IssueRating;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class SessionLifecycleIssues {

    static final String GUESSABLE = "Guessable MCP session IDs";
    static final String DELETED_REUSE = "MCP session usable after DELETE";
    private static final CheckDescriptor DESCRIPTOR = SessionLifecycleDescriptor.DESCRIPTOR;

    AuditIssue guessable(GuessableIds guessable, HttpRequestResponse base) {
        IssueBodyBuilder detail = new IssueBodyBuilder()
                .paragraph("The scanner opened " + guessable.ids().size() + " new MCP sessions of its own, one "
                        + "after another, and the server issued these session IDs:")
                .findings(guessable.ids())
                .paragraph("They are guessable:")
                .findings(guessable.weaknesses());
        attachedHandshakes(guessable.handshakes().size()).ifPresent(detail::paragraph);
        if (guessable.liveSessionReissued()) {
            detail.paragraph("The server issued the scanner's own live session ID to new sessions made with the "
                    + "same credentials. A server that keys one session per credential does this; an attacker "
                    + "without those credentials may not be able to learn the ID.");
        }
        guessable.bareUse().ifPresentOrElse(
                bare -> detail.paragraph("The server also answered a ping that carried only one of these session "
                        + "IDs, without credentials, while the same ping without a session ID was refused with HTTP "
                        + bare.refusedWithoutSession().response().statusCode() + " (not attached) and an "
                        + "initialize without credentials was refused with HTTP "
                        + bare.anonymousInitializeRefused().response().statusCode()
                        + ", so an anonymous client cannot open a session of its own. The session ID alone "
                        + "authenticates a request, so a guessed ID acts as another client's credential. A ping with a "
                        + "never-issued session ID and no credentials was refused with HTTP "
                        + bare.unissuedIdRefused().response().statusCode() + ", so the server checks which ID "
                        + "it is given. The unauthenticated request execution check reports the same root cause "
                        + "on the scanner's own session as \"MCP session id accepted as credential\"; this issue "
                        + "adds that the IDs can be guessed, which lets an attacker reach other clients' sessions. "
                        + "The refused initialize, the refused never-issued ID and the answered ping are attached"
                        + (guessable.handshakes().isEmpty() ? "." : " after the handshakes.")),
                () -> detail.paragraph("The scanner did not show that a session ID alone authenticates a request; "
                        + "the impact depends on what else the server binds to a session."));
        List<HttpRequestResponse> evidence = new ArrayList<>(guessable.handshakes());
        guessable.bareUse().ifPresent(bare -> {
            evidence.add(bare.anonymousInitializeRefused());
            evidence.add(bare.unissuedIdRefused());
            evidence.add(bare.answeredWithSessionOnly());
        });
        IssueRating rating = guessable.bareUse().isPresent()
                ? new IssueRating(AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM)
                : new IssueRating(AuditIssueSeverity.LOW, onlyTheLiveSession(guessable)
                        ? AuditIssueConfidence.TENTATIVE : AuditIssueConfidence.FIRM);
        return issue(GUESSABLE, detail.build(), guessableRemediation(), rating, base, evidence);
    }

    AuditIssue deletedReuse(DeletedSessionReuse reuse, HttpRequestResponse base) {
        IssueBodyBuilder detail = new IssueBodyBuilder()
                .paragraph("The scanner opened a new MCP session of its own; a ping with a never-issued session ID "
                        + "was refused with HTTP "
                        + reuse.unissuedIdRefused().response().statusCode() + ". It then ended the session with "
                        + "DELETE, which the server accepted with HTTP "
                        + reuse.delete().response().statusCode() + ".");
        reuse.answeredAfter().ifPresent(after -> detail.paragraph("A ping with the same Mcp-Session-Id was then "
                + "answered successfully, so the server did not end the session."));
        reuse.streamAfter().ifPresent(stream -> detail.paragraph("A GET request for the server's event stream with "
                + "the same Mcp-Session-Id then opened a text/event-stream response, while the same request with a "
                + "never-issued session ID was refused with HTTP "
                + stream.unissuedIdRejected().response().statusCode() + ", so the deleted session can still "
                + "receive server messages."));
        detail.paragraph("A client that ends its session expects the ID to stop working; anyone who later "
                + "obtains the ID can keep using the session. The scanner probed once, straight after "
                + "DELETE; a server that ends sessions asynchronously may refuse the ID shortly afterwards.");
        List<HttpRequestResponse> evidence = new ArrayList<>(List.of(reuse.unissuedIdRefused(), reuse.delete()));
        reuse.answeredAfter().ifPresent(evidence::add);
        reuse.streamAfter().ifPresent(stream -> {
            evidence.add(stream.openedAfterDelete());
            evidence.add(stream.unissuedIdRejected());
        });
        return issue(DELETED_REUSE, detail.build(), deletedReuseRemediation(),
                new IssueRating(AuditIssueSeverity.LOW, AuditIssueConfidence.FIRM), base, evidence);
    }

    private static Optional<String> attachedHandshakes(int count) {
        return switch (count) {
            case 0 -> Optional.empty();
            case 1 -> Optional.of("One of these session handshakes is attached, with the issued session ID "
                    + "highlighted.");
            default -> Optional.of("The first " + count + " of these session handshakes are attached, with the "
                    + "issued session ID highlighted in each.");
        };
    }

    private static boolean onlyTheLiveSession(GuessableIds guessable) {
        return guessable.liveSessionReissued() && guessable.ids().stream().distinct().count() == 1;
    }

    private static AuditIssue issue(String name, String detail, String remediation, IssueRating rating,
                                    HttpRequestResponse base, List<HttpRequestResponse> evidence) {
        return AuditIssue.auditIssue(name, detail, remediation, base.request().url(), rating.severity(),
                rating.confidence(), IssueMetadataRenderer.background(DESCRIPTOR.issueBackground(),
                        DESCRIPTOR.cwes(), DESCRIPTOR.references()),
                null, rating.severity(), evidence);
    }

    private static String guessableRemediation() {
        return new IssueBodyBuilder()
                .paragraph("Generate session IDs from a cryptographically secure random source with at least 128 "
                        + "bits of randomness, for example a version 4 UUID or 16 random bytes, encoded. Never "
                        + "derive them from a counter, a timestamp or a host identifier.")
                .paragraph("Do not treat a session ID as authentication: verify the client's credential on every "
                        + "request and bind each session to the identity that created it.")
                .build();
    }

    private static String deletedReuseRemediation() {
        return new IssueBodyBuilder()
                .paragraph("When a client sends DELETE with its Mcp-Session-Id, discard the session's state and "
                        + "answer any later request carrying that ID, including a GET for the event stream, with HTTP 404. If the server does not let "
                        + "clients end sessions, answer DELETE with HTTP 405 instead of a success status.")
                .build();
    }
}
