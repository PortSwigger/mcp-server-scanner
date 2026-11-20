package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.auth.CredentialHeaders;
import com.mcpscanner.checks.shared.probe.ProbeChannel;
import com.mcpscanner.checks.shared.stream.EventStreams;
import com.mcpscanner.checks.shared.stream.StreamOpening;
import com.mcpscanner.mcp.HttpOrigin;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.UnaryOperator;

final class StreamAdmissionTrial {

    static final int REQUEST_BUDGET = 20;

    private static final String ORIGIN = "Origin";

    private final EventStreams streams;
    private final CredentialHeaders credentials;

    StreamAdmissionTrial(EventStreams streams, CredentialHeaders credentials) {
        this.streams = streams;
        this.credentials = credentials;
    }

    Optional<TrialOutcome> run(HttpRequestResponse base, Http http) {
        ProbeChannel budget = new ProbeChannel(http, REQUEST_BUDGET);
        Function<AdmissionProbe, Optional<StreamOpening>> open =
                probe -> streams.open(base, http, budget, shapedBy(probe));
        AdmissionProbe sameOrigin = sameOriginControl(base.request());
        return open.apply(sameOrigin).map(control -> control.opened()
                ? probed(open, sameOrigin, control)
                : TrialOutcome.baselineNotSuccessful(control.exchange()));
    }

    private static TrialOutcome probed(Function<AdmissionProbe, Optional<StreamOpening>> open,
                                       AdmissionProbe sameOrigin, StreamOpening control) {
        List<ProbeObservation> observations = AdmissionProbe.STREAM_ORIGIN_SET.stream()
                .map(probe -> observe(probe, open.apply(probe)))
                .toList();
        Optional<StreamOpening> finalControl = open.apply(sameOrigin);
        TrialOutcome.TrialStatus status = finalControl.filter(StreamOpening::opened).isPresent()
                ? TrialOutcome.TrialStatus.CONCLUSIVE : TrialOutcome.TrialStatus.CONTROL_DIVERGED;
        return new TrialOutcome(status, control.exchange(), observations);
    }

    private UnaryOperator<HttpRequest> shapedBy(AdmissionProbe probe) {
        return request -> probe.applyTo(credentials.withMissingAdded(request));
    }

    private static ProbeObservation observe(AdmissionProbe probe, Optional<StreamOpening> opening) {
        return new ProbeObservation(probe, opening.map(StreamOpening::exchange).orElse(null),
                opening.map(StreamAdmissionTrial::verdictOf).orElse(ProbeVerdict.INCONCLUSIVE));
    }

    private static ProbeVerdict verdictOf(StreamOpening opening) {
        if (opening.opened()) {
            return ProbeVerdict.ADMITTED;
        }
        return opening.rejected() ? ProbeVerdict.REFUSED : ProbeVerdict.INCONCLUSIVE;
    }

    private static AdmissionProbe sameOriginControl(HttpRequest seed) {
        String own = HttpOrigin.of(seed.httpService()).baseUrl();
        return new AdmissionProbe(ORIGIN + ": " + own, AdmissionCategory.STREAM_ORIGIN, Map.of(ORIGIN, own));
    }
}
