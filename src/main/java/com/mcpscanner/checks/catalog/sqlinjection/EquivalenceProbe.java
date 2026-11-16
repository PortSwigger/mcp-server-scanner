package com.mcpscanner.checks.catalog.sqlinjection;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

final class EquivalenceProbe {

    static final int INSENSITIVE_FORMS_BEFORE_GIVING_UP = 4;

    private final Canaries canaries;

    EquivalenceProbe(Canaries canaries) {
        this.canaries = canaries;
    }

    SlotSurvey survey(ProbeField field, ValueSlot slot, Probe baseline) {
        List<Separation> separations = new ArrayList<>();
        Set<SyntaxFamily> separated = EnumSet.noneOf(SyntaxFamily.class);
        int insensitive = 0;
        for (SyntaxForm form : SyntaxForm.applicableTo(slot)) {
            if (field.gaveUp() || insensitive >= INSENSITIVE_FORMS_BEFORE_GIVING_UP || corroborated(separations)) {
                break;
            }
            if (separated.contains(form.family())) {
                continue;
            }
            String token = canaries.token();
            Probe equivalent = send(field, slot, form, token, true);
            if (!equivalent.shape().matches(baseline.shape())) {
                continue;
            }
            Separation pair = new Separation(form, equivalent, send(field, slot, form, token, false));
            if (pair.separates(baseline)) {
                separations.add(pair);
                separated.add(form.family());
            } else if (pair.falsifier().shape().matches(baseline.shape())) {
                insensitive++;
            }
        }
        return new SlotSurvey(slot, separations);
    }

    Separation repeat(ProbeField field, ValueSlot slot, SyntaxForm form) {
        String token = canaries.token();
        return new Separation(form, send(field, slot, form, token, true), send(field, slot, form, token, false));
    }

    private static boolean corroborated(List<Separation> separations) {
        SlotSurvey survey = new SlotSurvey(ValueSlot.whole(""), separations);
        return survey.sqlSpecific().isPresent() && survey.independentlyCorroborated();
    }

    private static Probe send(ProbeField field, ValueSlot slot, SyntaxForm form, String token, boolean equivalent) {
        String segment = slot.segment();
        return field.send(slot, equivalent ? form.equivalent(segment, token) : form.falsifier(segment, token));
    }
}
