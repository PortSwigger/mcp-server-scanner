package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.mcpscanner.checks.api.BrowserConsentObservation;
import com.mcpscanner.checks.api.SignedInProbe;

import java.util.List;
import java.util.Optional;

final class BrowserObservationFindings {

    private final List<BrowserConsentObservation> observations;

    private BrowserObservationFindings(List<BrowserConsentObservation> observations) {
        this.observations = observations;
    }

    static List<ConsentFinding> findings(List<BrowserConsentObservation> observations) {
        return new BrowserObservationFindings(observations).findings();
    }

    private List<ConsentFinding> findings() {
        List<BrowserConsentObservation> fired = observations.stream()
                .filter(BrowserConsentObservation::codeWithoutInteraction)
                .toList();
        List<BrowserConsentObservation> anyClient = fired.stream()
                .filter(observation -> observation.probe() == SignedInProbe.FRESH_NAME)
                .toList();
        return (anyClient.isEmpty() ? fired : anyClient).stream().map(this::finding).toList();
    }

    private ConsentFinding finding(BrowserConsentObservation observation) {
        FindingDraft draft = new FindingDraft(observation.authorizationEndpoint())
                .fact(SignedInFacts.observed(observation))
                .fact(SignedInFacts.BROWSER_LIMITS);
        Optional<String> inconclusiveControl = needsFreshNameControl(observation.probe())
                ? whyFreshNameControlInconclusive()
                : Optional.empty();
        inconclusiveControl.ifPresent(draft::fact);
        ConsentIssueKind kind = inconclusiveControl.isPresent()
                ? UncontrolledShortcut.INSTANCE
                : ConsentShortcut.of(observation.probe());
        return draft.as(kind, AuditIssueConfidence.TENTATIVE);
    }

    private static boolean needsFreshNameControl(SignedInProbe probe) {
        return probe != SignedInProbe.FRESH_NAME && probe != SignedInProbe.SCOPE_UPGRADE;
    }

    private Optional<String> whyFreshNameControlInconclusive() {
        Optional<BrowserConsentObservation> control = observations.stream()
                .filter(observation -> observation.probe() == SignedInProbe.FRESH_NAME)
                .reduce((earlier, later) -> later);
        if (control.isEmpty()) {
            return Optional.of(SignedInFacts.freshNameControlMissing());
        }
        return control.get().codeTooLateToCount()
                ? Optional.of(SignedInFacts.freshNameControlTooLate(control.get()))
                : Optional.empty();
    }
}
