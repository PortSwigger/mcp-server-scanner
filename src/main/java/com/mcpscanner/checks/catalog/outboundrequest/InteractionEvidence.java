package com.mcpscanner.checks.catalog.outboundrequest;

import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionType;
import burp.api.montoya.http.message.HttpHeader;
import com.mcpscanner.checks.shared.collaborator.InteractionDescription;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

record InteractionEvidence(List<Interaction> interactions) {

    private static final Pattern CREDENTIAL_HEADER = Pattern.compile(
            "authorization|proxy-authorization|cookie|.*token.*|.*api-?key.*|.*secret.*|.*password.*");

    InteractionEvidence {
        interactions = List.copyOf(interactions);
    }

    InteractionStrength strength() {
        return interactions.stream().anyMatch(interaction -> interaction.type() == InteractionType.HTTP)
                ? InteractionStrength.HTTP_REQUEST
                : InteractionStrength.DNS_LOOKUP_ONLY;
    }

    List<String> forwardedCredentialHeaders(ProbeUserInfo suppliedByProbe) {
        return interactions.stream()
                .map(InteractionDescription::httpRequestOf)
                .flatMap(Optional::stream)
                .flatMap(request -> request.headers().stream())
                .filter(InteractionEvidence::carriesCredential)
                .filter(header -> !suppliedByProbe.supplied(header))
                .map(HttpHeader::name)
                .distinct()
                .toList();
    }

    private static boolean carriesCredential(HttpHeader header) {
        return header.value() != null && !header.value().isBlank()
                && CREDENTIAL_HEADER.matcher(header.name().toLowerCase(Locale.ROOT)).matches();
    }
}
