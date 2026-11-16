package com.mcpscanner.checks.catalog.commandinjection;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

final class OptionInjectionProbe {

    private static final String TECHNIQUE = "command-line option injection";

    ProbeOutcome probe(ProbeField field, InjectionReply baseline) {
        for (ProgramOption option : ProgramOption.values()) {
            ProbeOutcome result = probe(field, baseline, option);
            if (result.conclusive()) {
                return result;
            }
        }
        return ProbeOutcome.inconclusive();
    }

    private static ProbeOutcome probe(ProbeField field, InjectionReply baseline, ProgramOption option) {
        InjectionReply optioned = field.send(option.flag());
        List<Lead> leads = optioned.answered() ? leads(baseline, optioned, option) : List.of();
        if (leads.isEmpty()) {
            return ProbeOutcome.inconclusive();
        }
        InjectionReply undashed = field.send(option.undashed());
        List<Lead> confirmed = narrowed(leads, undashed, option, false);
        if (confirmed.isEmpty()) {
            return ProbeOutcome.inconclusive();
        }
        InjectionReply repeated = field.send(option.flag());
        return narrowed(confirmed, repeated, option, true).stream().findFirst()
                .map(lead -> found(field, option, lead, baseline, optioned, undashed, repeated))
                .orElseGet(ProbeOutcome::inconclusive);
    }

    private static List<Lead> leads(InjectionReply baseline, InjectionReply optioned, ProgramOption option) {
        return Arrays.stream(OptionDisclosure.values())
                .map(kind -> new Lead(kind, kind.in(optioned.text(), option)).without(baseline, option))
                .filter(Lead::enough)
                .toList();
    }

    private static List<Lead> narrowed(List<Lead> leads, InjectionReply reply, ProgramOption option,
                                       boolean keepShared) {
        if (!reply.answered()) {
            return List.of();
        }
        return leads.stream()
                .map(lead -> keepShared ? lead.within(reply, option) : lead.without(reply, option))
                .filter(Lead::enough)
                .toList();
    }

    private static ProbeOutcome found(ProbeField field, ProgramOption option, Lead disclosed,
                                      InjectionReply... replies) {
        String technique = TECHNIQUE + ": the value " + option.flag() + " returned " + disclosed.kind().described()
                + " (" + String.join(", ", disclosed.tokens()) + ") twice, which the value " + option.undashed()
                + " did not";
        return ProbeOutcome.found(Finding.proving(FindingKind.OPTION_INJECTION, field.subject(), technique,
                List.copyOf(disclosed.tokens()), replies));
    }

    private record Lead(OptionDisclosure kind, Set<String> tokens) {

        boolean enough() {
            return kind.enough(tokens);
        }

        Lead without(InjectionReply reply, ProgramOption option) {
            Set<String> remaining = new TreeSet<>(tokens);
            remaining.removeAll(kind.in(reply.text(), option));
            return new Lead(kind, remaining);
        }

        Lead within(InjectionReply reply, ProgramOption option) {
            Set<String> remaining = new TreeSet<>(tokens);
            remaining.retainAll(kind.in(reply.text(), option));
            return new Lead(kind, remaining);
        }
    }
}
