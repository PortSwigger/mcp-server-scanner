package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.InteractionType;
import com.mcpscanner.checks.shared.collaborator.ObservedInteractions;
import com.mcpscanner.checks.shared.collaborator.PayloadSource;

import java.util.ArrayList;
import java.util.List;

record ControlledLead(Lead lead, CollaboratorPayload payload, SentUrl control) {

    static List<ControlledLead> send(FieldSender sender, Ipv4Literal collaborator, List<Lead> leads,
                                     PayloadSource payloads) {
        List<ControlledLead> controlled = new ArrayList<>();
        for (Lead lead : leads) {
            payloads.newPayload().ifPresent(payload -> controlled.add(send(sender, collaborator, lead, payload)));
        }
        return controlled;
    }

    private static ControlledLead send(FieldSender sender, Ipv4Literal collaborator, Lead lead,
                                       CollaboratorPayload payload) {
        return new ControlledLead(lead, payload,
                sender.send(ProbeUrl.control(lead.spelling().controlHost(collaborator), payload)));
    }

    boolean fetchedBy(ObservedInteractions observed) {
        return observed.of(payload).stream().anyMatch(interaction -> interaction.type() == InteractionType.HTTP);
    }
}
