package com.mcpscanner.checks.catalog.commandinjection;

import java.util.List;

final class GenericEvaluatorProbe {

    private final CanarySource confirmations;

    GenericEvaluatorProbe(CanarySource confirmations) {
        this.confirmations = confirmations;
    }

    ProbeOutcome probe(ProbeField field, InjectionReply baseline, ArithmeticCanary canary) {
        String computed = canary.result();
        for (InterpreterBreakout breakout : InterpreterBreakout.values()) {
            ProbeOutcome result = probe(field, baseline, computed, breakout);
            if (result.conclusive()) {
                return result;
            }
        }
        for (EvaluatorFamily family : EvaluatorFamily.values()) {
            ProbeOutcome result = probe(field, baseline, computed, family);
            if (result.conclusive()) {
                return result;
            }
        }
        return ProbeOutcome.inconclusive();
    }

    private ProbeOutcome probe(ProbeField field, InjectionReply baseline, String computed, InterpreterBreakout breakout) {
        InjectionReply injected = field.send(breakout.payload(field.original(), computed));
        if (!evaluated(injected, computed)) {
            return ProbeOutcome.inconclusive();
        }
        InjectionReply matched = field.sendMatchedControl();
        if (!matched.answered() || matched.contains(computed)) {
            return ProbeOutcome.inconclusive();
        }
        InjectionReply bare = field.confirm(breakout.bareDecoder(computed));
        if (evaluated(bare, computed)) {
            return ProbeOutcome.found(Finding.proving(FindingKind.EVALUATED_ARGUMENT, field.subject(),
                    breakout.label(), List.of(computed), baseline, bare));
        }
        String fresh = confirmations.next().result();
        InjectionReply repeated = field.confirm(breakout.payload(field.original(), fresh));
        if (!evaluated(repeated, fresh)) {
            return ProbeOutcome.inconclusive();
        }
        return ProbeOutcome.found(Finding.proving(FindingKind.INTERPRETER_COMPUTED_RESULT, field.subject(),
                breakout.label(), List.of(computed), baseline, injected, bare));
    }

    private ProbeOutcome probe(ProbeField field, InjectionReply baseline, String computed, EvaluatorFamily family) {
        String payload = family.payload(computed);
        InjectionReply evaluated = field.send(payload);
        if (!evaluated(evaluated, computed)) {
            return ProbeOutcome.inconclusive();
        }
        InjectionReply matched = field.sendMatchedControl();
        if (!matched.answered() || matched.contains(computed)) {
            return ProbeOutcome.inconclusive();
        }
        InjectionReply literal = field.confirm(family.literalControl(payload));
        if (!literal.successful() || literal.contains(computed) || !literal.contains(payload)) {
            return ProbeOutcome.inconclusive();
        }
        return ProbeOutcome.found(Finding.proving(FindingKind.EVALUATED_ARGUMENT, field.subject(), family.label(),
                List.of(computed), baseline, evaluated, literal));
    }

    private static boolean evaluated(InjectionReply reply, String computed) {
        return reply.successful() && reply.contains(computed);
    }
}
