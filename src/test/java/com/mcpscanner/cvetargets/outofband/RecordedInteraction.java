package com.mcpscanner.cvetargets.outofband;

import burp.api.montoya.collaborator.DnsDetails;
import burp.api.montoya.collaborator.DnsQueryType;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionId;
import burp.api.montoya.collaborator.InteractionType;
import burp.api.montoya.collaborator.SmtpDetails;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpProtocol;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

record RecordedInteraction(String identifier, InteractionType type, ZonedDateTime timeStamp, InetAddress clientIp,
                           int clientPort, Optional<DnsDetails> dnsDetails, Optional<HttpDetails> httpDetails)
        implements Interaction {

    static RecordedInteraction from(JsonNode entry) {
        InteractionType type = InteractionType.valueOf(entry.path("type").asText());
        return new RecordedInteraction(entry.path("id").asText(), type,
                Instant.ofEpochMilli((long) (entry.path("time").asDouble() * 1000)).atZone(ZoneOffset.UTC),
                address(entry.path("clientIp").asText()), entry.path("clientPort").asInt(),
                type == InteractionType.DNS ? Optional.of(dns(entry)) : Optional.empty(),
                type == InteractionType.HTTP ? Optional.of(http(entry)) : Optional.empty());
    }

    @Override
    public InteractionId id() {
        return new RecorderInteractionId(identifier);
    }

    @Override
    public Optional<SmtpDetails> smtpDetails() {
        return Optional.empty();
    }

    @Override
    public Optional<String> customData() {
        return Optional.empty();
    }

    private static DnsDetails dns(JsonNode entry) {
        DnsQueryType queryType = Arrays.stream(DnsQueryType.values())
                .filter(candidate -> candidate.name().equals(entry.path("queryType").asText()))
                .findFirst().orElse(DnsQueryType.A);
        ByteArray query = ByteArray.byteArray(entry.path("query").asText());
        return new DnsDetails() {
            @Override
            public DnsQueryType queryType() {
                return queryType;
            }

            @Override
            public ByteArray query() {
                return query;
            }
        };
    }

    private static HttpDetails http(JsonNode entry) {
        HttpRequestResponse exchange = HttpRequestResponse.httpRequestResponse(
                RawRequests.parse(Base64.getDecoder().decode(entry.path("request").asText())), null);
        HttpProtocol protocol = HttpProtocol.valueOf(entry.path("protocol").asText(HttpProtocol.HTTP.name()));
        return new HttpDetails() {
            @Override
            public HttpProtocol protocol() {
                return protocol;
            }

            @Override
            public HttpRequestResponse requestResponse() {
                return exchange;
            }
        };
    }

    private static InetAddress address(String text) {
        try {
            return InetAddress.getByName(text);
        } catch (UnknownHostException e) {
            return InetAddress.getLoopbackAddress();
        }
    }
}
