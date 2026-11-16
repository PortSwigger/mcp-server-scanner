package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.checks.api.HostSettlement;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.stream.StreamEvidenceNote;
import com.mcpscanner.checks.shared.stream.StreamGetRequest;
import com.mcpscanner.checks.shared.stream.StreamOpener;
import com.mcpscanner.checks.shared.stream.StreamOpening;
import com.mcpscanner.http.BareRequests;
import com.mcpscanner.mcp.SseProbeStreams;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

final class StreamCorsRead {

    private static final String SCOPE = "The scanner opened the legacy SSE event stream with no credentials and "
            + "only a foreign Origin header, as a cross-site page's EventSource would. A browser opens such a "
            + "stream without a CORS preflight, and the stream carries the session's message endpoint and every "
            + "reply. " + StreamEvidenceNote.OPENED_OUTSIDE_BURP;

    private final CheckLog log;
    private final Supplier<Optional<SseProbeStreams>> sseStreams;
    private final StreamOpener opener;

    StreamCorsRead(CheckLog log, Supplier<Optional<SseProbeStreams>> sseStreams, StreamOpener opener) {
        this.log = log;
        this.sseStreams = sseStreams;
        this.opener = opener;
    }

    Optional<String> streamUrl() {
        return sseStreams.get().flatMap(SseProbeStreams::streamUrl);
    }

    CorsReading read(Http http, String test) {
        Optional<String> url = streamUrl();
        if (url.isEmpty()) {
            log.notRun(test, SkipReason.prerequisiteMissing("the legacy SSE stream URL is unknown"));
            return CorsReading.nothingFound(HostSettlement.SETTLED);
        }
        StreamOpening opening = opener.reportingTo(http).open(anonymousGet(url.get()));
        if (!opening.answered()) {
            log.notRun(test, SkipReason.transportFailure("the cross-origin event stream got no response"));
            return CorsReading.nothingFound(HostSettlement.INCONCLUSIVE);
        }
        CorsGrant grant = CorsGrant.of(opening.exchange());
        if (!opening.opened() || !grant.approves(CorsProbe.FOREIGN_ORIGIN)) {
            log.info("decision: the anonymous cross-origin event stream is not readable (" + opening.status()
                    + ", opened " + opening.opened() + ", " + grant.describe() + ")");
            return CorsReading.nothingFound(HostSettlement.SETTLED);
        }
        log.info("decision: CORS lets " + CorsProbe.FOREIGN_ORIGIN + " read the anonymous event stream");
        return CorsReading.found(new CorsFinding(SCOPE, CorsAuth.NONE, false,
                List.of(new CorsEvidence("the event stream", opening.exchange(), false))));
    }

    private static HttpRequest anonymousGet(String streamUrl) {
        return BareRequests.fromUrl(streamUrl)
                .withHeader("Accept", StreamGetRequest.EVENT_STREAM)
                .withHeader("Origin", CorsProbe.FOREIGN_ORIGIN);
    }
}
