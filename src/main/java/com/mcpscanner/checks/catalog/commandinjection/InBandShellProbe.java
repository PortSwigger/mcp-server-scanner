package com.mcpscanner.checks.catalog.commandinjection;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

final class InBandShellProbe {

    private static final String TECHNIQUE = "shell arithmetic expansion";

    private final CanarySource confirmations;

    InBandShellProbe(CanarySource confirmations) {
        this.confirmations = confirmations;
    }

    ProbeOutcome probe(ProbeField field, InjectionReply baseline, ArithmeticCanary canary) {
        for (ShellBreakout breakout : field.breakouts()) {
            ProbeOutcome result = probe(field, baseline, canary, breakout);
            if (result.conclusive()) {
                return result;
            }
        }
        return ProbeOutcome.inconclusive();
    }

    private ProbeOutcome probe(ProbeField field, InjectionReply baseline, ArithmeticCanary canary, ShellBreakout breakout) {
        String computed = canary.result();
        InjectionReply injected = field.send(breakout.wrap(field.original(), canary.command()));
        if (!injected.answered() || !injected.contains(computed)) {
            return ProbeOutcome.inconclusive();
        }
        InjectionReply direct = field.confirm(canary.command());
        if (computes(direct, canary)) {
            return found(FindingKind.INTENDED_COMMAND, field, List.of(computed), baseline, injected, direct);
        }
        InjectionReply matched = field.sendMatchedControl();
        if (matched.successful() && !matched.contains(computed)) {
            return confirmed(FindingKind.SHELL_COMPUTED_RESULT, field, breakout, computed, baseline, injected, direct);
        }
        if (!matched.rejected() || matched.contains(computed)) {
            return ProbeOutcome.inconclusive();
        }
        InjectionReply quoted = field.confirm(breakout.wrap(field.original(), canary.quotedCommand()));
        if (quoted.answered() && !quoted.contains(computed) && quoted.contains(canary.quotedLiteral())) {
            return confirmed(FindingKind.SHELL_COMPUTED_RESULT_QUOTED_CONTROL, field, breakout, computed, baseline,
                    injected, direct, quoted);
        }
        return ProbeOutcome.inconclusive();
    }

    private ProbeOutcome confirmed(FindingKind kind, ProbeField field, ShellBreakout breakout, String computed,
                                   InjectionReply baseline, InjectionReply injected, InjectionReply... controls) {
        ArithmeticCanary fresh = confirmations.next();
        InjectionReply repeated = field.confirm(breakout.wrap(field.original(), fresh.command()));
        if (!computes(repeated, fresh)) {
            return ProbeOutcome.inconclusive();
        }
        InjectionReply repeatedDirect = field.confirm(fresh.command());
        if (computes(repeatedDirect, fresh)) {
            return found(FindingKind.INTENDED_COMMAND, field, List.of(computed, fresh.result()), baseline, injected,
                    repeatedDirect);
        }
        InjectionReply[] evidence = Stream.concat(Stream.of(baseline, injected), Arrays.stream(controls))
                .toArray(InjectionReply[]::new);
        return found(kind, field, List.of(computed), evidence);
    }

    private static boolean computes(InjectionReply reply, ArithmeticCanary canary) {
        return reply.answered() && reply.contains(canary.result());
    }

    private static ProbeOutcome found(FindingKind kind, ProbeField field, List<String> proofs,
                                      InjectionReply... replies) {
        return ProbeOutcome.found(Finding.proving(kind, field.subject(), TECHNIQUE, proofs, replies));
    }
}
