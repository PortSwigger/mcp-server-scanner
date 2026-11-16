package com.mcpscanner.checks.catalog.sqlinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

final class Confirmation {

    static final int ROUNDS = 3;

    private final EquivalenceProbe equivalence;
    private final StatementControl statements;

    Confirmation(EquivalenceProbe equivalence, StatementControl statements) {
        this.equivalence = equivalence;
        this.statements = statements;
    }

    Verdict confirm(ProbeField field, SlotSurvey survey, Probe baseline) {
        SyntaxForm primary = survey.sqlSpecific().orElseThrow().form();
        if (survey.slot().isWhole() && statements.runsWholeStatements(field)) {
            return Verdict.BY_DESIGN;
        }
        List<ConfirmationRound> rounds = new ArrayList<>();
        for (int round = 0; round < ROUNDS; round++) {
            ConfirmationRound confirmed = round(field, survey.slot(), primary, round);
            rounds.add(confirmed);
            if (!confirmed.agrees(baseline)) {
                return Verdict.UNSTABLE;
            }
        }
        return Verdict.confirmed(new Finding(survey.slot(), forms(survey),
                survey.independentlyCorroborated() ? AuditIssueConfidence.FIRM : AuditIssueConfidence.TENTATIVE,
                evidence(survey, baseline, rounds)));
    }

    private ConfirmationRound round(ProbeField field, ValueSlot slot, SyntaxForm form, int round) {
        if (round % 2 == 0) {
            Probe resent = resend(field);
            return new ConfirmationRound(resent, equivalence.repeat(field, slot, form));
        }
        Separation repeated = equivalence.repeat(field, slot, form);
        return new ConfirmationRound(resend(field), repeated);
    }

    private static Probe resend(ProbeField field) {
        return field.send(ValueSlot.whole(field.original()), field.original());
    }

    private static List<SyntaxForm> forms(SlotSurvey survey) {
        return survey.separations().stream().map(Separation::form).toList();
    }

    private static List<HttpRequestResponse> evidence(SlotSurvey survey, Probe baseline,
                                                      List<ConfirmationRound> rounds) {
        Stream<Probe> surveyed = survey.separations().stream()
                .flatMap(separation -> Stream.of(separation.equivalent(), separation.falsifier()));
        Stream<Probe> confirmed = rounds.stream().flatMap(round -> round.probes().stream());
        return Stream.of(Stream.of(baseline), surveyed, confirmed)
                .flatMap(probes -> probes)
                .map(Probe::exchange)
                .toList();
    }
}
