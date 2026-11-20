package com.mcpscanner.scan;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.field.MetaEnvelope;
import com.mcpscanner.scan.field.MetaEnvelopeRegistry;
import com.mcpscanner.scan.field.MetaEnvelopeRegistry.Role;
import com.mcpscanner.scan.request.RequestFamilyGroup;
import com.mcpscanner.scan.request.ScanMessage;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.stream.IntStream;

public final class MetaEnvelopeCarriers {

    private static final Set<RequestFamilyGroup> CHEAP_GROUPS = Set.of(RequestFamilyGroup.LISTING,
            RequestFamilyGroup.LIFECYCLE);

    private final MetaEnvelopeRegistry registry;
    private final BooleanSupplier fuzzedOnEveryRequest;
    private final McpEventLog eventLog;

    public MetaEnvelopeCarriers(MetaEnvelopeRegistry registry, BooleanSupplier fuzzedOnEveryRequest,
                                McpEventLog eventLog) {
        this.registry = Objects.requireNonNull(registry);
        this.fuzzedOnEveryRequest = Objects.requireNonNull(fuzzedOnEveryRequest);
        this.eventLog = Objects.requireNonNull(eventLog);
    }

    public static MetaEnvelopeCarriers onEveryRequest() {
        return new MetaEnvelopeCarriers(new MetaEnvelopeRegistry(), () -> true, McpEventLog.noop());
    }

    public Runnable hold(List<ScanMessage> messages, List<HttpRequest> requests) {
        if (fuzzedOnEveryRequest.getAsBoolean()) {
            return () -> { };
        }
        List<Held> held = new ArrayList<>();
        baseRequestsByServer(messages, requests).forEach((server, bases) -> held.addAll(holdsFor(server, bases)));
        held.forEach(hold -> registry.hold(hold.body(), hold.role()));
        return () -> held.forEach(hold -> registry.release(hold.body(), hold.role()));
    }

    private List<Held> holdsFor(String server, List<Base> bases) {
        Base carrier = bases.stream().filter(Base::carriesEnvelope)
                .min(Comparator.comparingInt(Base::carrierRank)).orElse(null);
        if (carrier == null) {
            return List.of();
        }
        eventLog.info("Request metadata (_meta) is fuzzed once for " + server + ", on " + carrier.message().subject());
        return bases.stream()
                .map(base -> new Held(base.body(), base == carrier ? Role.CARRIER : Role.PASSENGER)).toList();
    }

    private static Map<String, List<Base>> baseRequestsByServer(List<ScanMessage> messages,
                                                                List<HttpRequest> requests) {
        Map<String, List<Base>> byServer = new LinkedHashMap<>();
        IntStream.range(0, messages.size())
                .filter(i -> messages.get(i).addedArgument().isEmpty())
                .mapToObj(i -> new Base(messages.get(i), requests.get(i)))
                .forEach(base -> byServer.computeIfAbsent(serverOf(base.request()), key -> new ArrayList<>()).add(base));
        return byServer;
    }

    private static String serverOf(HttpRequest request) {
        HttpService service = request.httpService();
        String path = Objects.requireNonNullElse(request.path(), "");
        int query = path.indexOf('?');
        return (service.secure() ? "https://" : "http://") + service.host() + ":" + service.port()
                + (query < 0 ? path : path.substring(0, query));
    }

    private record Base(ScanMessage message, HttpRequest request) {

        String body() {
            return request.bodyToString();
        }

        boolean carriesEnvelope() {
            return MetaEnvelope.carriedBy(request.body().getBytes());
        }

        int carrierRank() {
            RequestFamilyGroup group = message.family().group();
            if (CHEAP_GROUPS.contains(group)) {
                return 0;
            }
            return group == RequestFamilyGroup.NOTIFICATIONS ? 2 : 1;
        }
    }

    private record Held(String body, Role role) {}
}
