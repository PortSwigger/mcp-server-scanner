package com.mcpscanner.testutil;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.Arrays;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.RETURNS_DEFAULTS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

public final class MontoyaTestFactory {

    private MontoyaTestFactory() {}

    private static MontoyaObjectFactory installed;

    public static synchronized void install() {
        if (installed == null) {
            installed = stubbedFactory();
        }
        ObjectFactoryLocator.FACTORY = installed;
    }

    private static MontoyaObjectFactory stubbedFactory() {
        MontoyaObjectFactory factory = mock(MontoyaObjectFactory.class, withSettings().stubOnly());
        installAuditResultStubs(factory);
        installAuditIssueStubs(factory);
        installHttpServiceStubs(factory);
        installHttpRequestStubs(factory);
        installHttpRequestResponseStub(factory);
        installHttpHandlerStubs(factory);
        installAuditInsertionPointStub(factory);
        installAuditConfigurationStub(factory);
        installRangeStub(factory);
        installByteArrayStub(factory);
        installRequestOptionsStub(factory);
        return factory;
    }

    private static void installRequestOptionsStub(MontoyaObjectFactory factory) {
        lenient().when(factory.requestOptions()).thenAnswer(invocation -> new RecordingRequestOptions());
    }

    private static void installHttpRequestResponseStub(MontoyaObjectFactory factory) {
        lenient().when(factory.httpRequestResponse(any(HttpRequest.class), nullable(HttpResponse.class)))
                .thenAnswer(invocation -> requestResponseMock(invocation.getArgument(0), invocation.getArgument(1),
                        List.of(), List.of()));
        lenient().when(factory.marker(anyInt(), anyInt())).thenAnswer(invocation ->
                markerMock(Range.range(invocation.getArgument(0), invocation.getArgument(1))));
        lenient().when(factory.marker(any(Range.class))).thenAnswer(invocation -> markerMock(invocation.getArgument(0)));
    }

    @SuppressWarnings("unchecked")
    private static HttpRequestResponse requestResponseMock(HttpRequest request, HttpResponse response,
                                                           List<Marker> requestMarkers, List<Marker> responseMarkers) {
        HttpRequestResponse rr = mock(HttpRequestResponse.class, withSettings().stubOnly());
        lenient().when(rr.request()).thenReturn(request);
        lenient().when(rr.response()).thenReturn(response);
        lenient().when(rr.hasResponse()).thenReturn(response != null);
        lenient().when(rr.httpService()).thenAnswer(ignored -> request.httpService());
        lenient().when(rr.requestMarkers()).thenReturn(requestMarkers);
        lenient().when(rr.responseMarkers()).thenReturn(responseMarkers);
        lenient().when(rr.withRequestMarkers(anyList())).thenAnswer(invocation -> requestResponseMock(request, response,
                List.copyOf((List<Marker>) invocation.getArgument(0)), responseMarkers));
        lenient().when(rr.withResponseMarkers(anyList())).thenAnswer(invocation -> requestResponseMock(request,
                response, requestMarkers, List.copyOf((List<Marker>) invocation.getArgument(0))));
        return rr;
    }

    private static Marker markerMock(Range range) {
        Marker marker = mock(Marker.class, withSettings().stubOnly());
        lenient().when(marker.range()).thenReturn(range);
        return marker;
    }

    private static void installAuditResultStubs(MontoyaObjectFactory factory) {
        lenient().when(factory.auditResult(anyList())).thenAnswer(invocation -> {
            List<AuditIssue> issues = invocation.getArgument(0);
            AuditResult result = mock(AuditResult.class);
            lenient().when(result.auditIssues()).thenReturn(issues);
            return result;
        });

        lenient().when(factory.auditResult(any(AuditIssue[].class))).thenAnswer(invocation -> {
            AuditIssue[] issues = (AuditIssue[]) invocation.getRawArguments()[0];
            AuditResult result = mock(AuditResult.class);
            lenient().when(result.auditIssues()).thenReturn(Arrays.asList(issues));
            return result;
        });
    }

    private static void installAuditIssueStubs(MontoyaObjectFactory factory) {
        lenient().when(factory.auditIssue(
                anyString(), anyString(), anyString(), anyString(),
                any(AuditIssueSeverity.class), any(AuditIssueConfidence.class),
                nullable(String.class), nullable(String.class),
                any(AuditIssueSeverity.class), anyList()
        )).thenAnswer(invocation -> createMockIssue(
                invocation.getArgument(0),
                invocation.getArgument(1),
                invocation.getArgument(2),
                invocation.getArgument(3),
                invocation.getArgument(4),
                invocation.getArgument(5),
                invocation.getArgument(6),
                invocation.getArgument(7),
                invocation.getArgument(8),
                invocation.getArgument(9)));

        lenient().when(factory.auditIssue(
                anyString(), anyString(), anyString(), anyString(),
                any(AuditIssueSeverity.class), any(AuditIssueConfidence.class),
                nullable(String.class), nullable(String.class),
                any(AuditIssueSeverity.class), any(HttpRequestResponse[].class)
        )).thenAnswer(invocation -> createMockIssue(
                invocation.getArgument(0),
                invocation.getArgument(1),
                invocation.getArgument(2),
                invocation.getArgument(3),
                invocation.getArgument(4),
                invocation.getArgument(5),
                invocation.getArgument(6),
                invocation.getArgument(7),
                invocation.getArgument(8),
                Arrays.asList((HttpRequestResponse[]) invocation.getRawArguments()[9])));
    }

    private static void installHttpServiceStubs(MontoyaObjectFactory factory) {
        lenient().when(factory.httpService(anyString()))
                .thenAnswer(invocation -> {
                    HttpService service = mock(HttpService.class);
                    lenient().when(service.host()).thenReturn(invocation.getArgument(0));
                    return service;
                });

        lenient().when(factory.httpService(anyString(), anyInt(), anyBoolean()))
                .thenAnswer(invocation -> {
                    HttpService service = mock(HttpService.class);
                    lenient().when(service.host()).thenReturn(invocation.getArgument(0));
                    lenient().when(service.port()).thenReturn(invocation.getArgument(1));
                    lenient().when(service.secure()).thenReturn(invocation.getArgument(2));
                    return service;
                });
    }

    private static void installHttpRequestStubs(MontoyaObjectFactory factory) {
        lenient().when(factory.httpRequest(any(HttpService.class), anyString()))
                .thenAnswer(invocation -> mock(HttpRequest.class));

        lenient().when(factory.httpRequest(anyString()))
                .thenReturn(mock(HttpRequest.class));

        lenient().when(factory.httpRequestFromUrl(anyString())).thenAnswer(invocation -> {
            String url = invocation.getArgument(0);
            return buildHttpRequestMock(url);
        });

        lenient().when(factory.httpResponse(anyString())).thenAnswer(invocation -> {
            String raw = invocation.getArgument(0);
            return buildHttpResponseMock(raw);
        });

        lenient().when(factory.httpResponse(any(ByteArray.class))).thenAnswer(invocation -> {
            ByteArray raw = invocation.getArgument(0);
            return buildHttpResponseMock(raw.getBytes());
        });
    }

    private static HttpRequest buildHttpRequestMock(String url) {
        return requestMock(new RequestState(url, "GET", "", new java.util.LinkedHashMap<>(), buildHttpServiceMock(url)));
    }

    private record RequestState(String url, String method, String body,
                                java.util.Map<String, String> headers, HttpService service) {

        RequestState withMethod(String newMethod) {
            return new RequestState(url, newMethod, body, headers, service);
        }

        RequestState withBody(String newBody) {
            return new RequestState(url, method, newBody, headers, service);
        }

        RequestState withService(HttpService newService) {
            return new RequestState(url, method, body, headers, newService);
        }

        RequestState withTarget(String target) {
            java.net.URI uri = java.net.URI.create(url);
            return new RequestState(uri.getScheme() + "://" + uri.getRawAuthority() + target, method, body, headers,
                    service);
        }

        RequestState withoutHeader(String name) {
            java.util.Map<String, String> copy = new java.util.LinkedHashMap<>(headers);
            copy.keySet().removeIf(key -> key.equalsIgnoreCase(name));
            return new RequestState(url, method, body, copy, service);
        }

        RequestState withHeader(String name, String value) {
            java.util.Map<String, String> copy = new java.util.LinkedHashMap<>(headers);
            copy.put(name, value);
            return new RequestState(url, method, body, copy, service);
        }

        RequestState withUpdatedHeader(String name, String value) {
            java.util.Map<String, String> copy = new java.util.LinkedHashMap<>(headers);
            copy.keySet().removeIf(existing -> existing.equalsIgnoreCase(name));
            copy.put(name, value);
            return new RequestState(url, method, body, copy, service);
        }

        boolean hasHeader(String name) {
            return headers.keySet().stream().anyMatch(existing -> existing.equalsIgnoreCase(name));
        }

        byte[] head() {
            StringBuilder head = new StringBuilder(method).append(' ').append(pathOf(url)).append(" HTTP/1.1\r\n");
            headers.forEach((name, value) -> head.append(name).append(": ").append(value).append("\r\n"));
            return head.append("\r\n").toString().getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        }

        byte[] wire() {
            byte[] head = head();
            byte[] bodyBytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] whole = java.util.Arrays.copyOf(head, head.length + bodyBytes.length);
            System.arraycopy(bodyBytes, 0, whole, head.length, bodyBytes.length);
            return whole;
        }

        RequestState withoutHeaders(List<?> removed) {
            java.util.Map<String, String> copy = new java.util.LinkedHashMap<>(headers);
            removed.stream()
                    .filter(HttpHeader.class::isInstance)
                    .map(HttpHeader.class::cast)
                    .forEach(header -> copy.remove(header.name()));
            return new RequestState(url, method, body, copy, service);
        }
    }

    private static HttpRequest requestMock(RequestState state) {
        HttpRequest request = mock(HttpRequest.class, withSettings().stubOnly());
        lenient().when(request.withMethod(anyString()))
                .thenAnswer(inv -> requestMock(state.withMethod(inv.getArgument(0))));
        lenient().when(request.withBody(anyString()))
                .thenAnswer(inv -> requestMock(state.withBody(inv.getArgument(0))));
        lenient().when(request.withService(any(HttpService.class)))
                .thenAnswer(inv -> requestMock(state.withService(inv.getArgument(0))));
        lenient().when(request.withAddedHeader(anyString(), anyString()))
                .thenAnswer(inv -> requestMock(state.withHeader(inv.getArgument(0), inv.getArgument(1))));
        lenient().when(request.withHeader(anyString(), anyString()))
                .thenAnswer(inv -> requestMock(state.withUpdatedHeader(inv.getArgument(0), inv.getArgument(1))));
        lenient().when(request.withUpdatedHeader(anyString(), anyString()))
                .thenAnswer(inv -> requestMock(state.withUpdatedHeader(inv.getArgument(0), inv.getArgument(1))));
        lenient().when(request.hasHeader(anyString())).thenAnswer(inv -> state.hasHeader(inv.getArgument(0)));
        lenient().when(request.bodyOffset()).thenAnswer(inv -> state.head().length);
        lenient().when(request.toByteArray()).thenAnswer(inv -> ByteArray.byteArray(state.wire()));
        lenient().when(request.withRemovedHeaders(anyList()))
                .thenAnswer(inv -> requestMock(state.withoutHeaders(inv.getArgument(0))));
        lenient().when(request.withRemovedHeader(anyString()))
                .thenAnswer(inv -> requestMock(state.withoutHeader(inv.getArgument(0))));
        lenient().when(request.withPath(anyString()))
                .thenAnswer(inv -> requestMock(state.withTarget(inv.getArgument(0))));
        lenient().when(request.method()).thenReturn(state.method());
        lenient().when(request.bodyToString()).thenReturn(state.body());
        lenient().when(request.body()).thenAnswer(inv ->
                ByteArray.byteArray(state.body().getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        lenient().when(request.withBody(any(ByteArray.class))).thenAnswer(inv -> requestMock(state.withBody(
                new String(((ByteArray) inv.getArgument(0)).getBytes(), java.nio.charset.StandardCharsets.UTF_8))));
        lenient().when(request.headerValue(anyString()))
                .thenAnswer(inv -> state.headers().get((String) inv.getArgument(0)));
        lenient().when(request.httpService()).thenReturn(state.service());
        lenient().when(request.headers()).thenAnswer(inv -> state.headers().entrySet().stream()
                .map(e -> buildHeaderMock(e.getKey(), e.getValue()))
                .toList());
        lenient().when(request.url()).thenReturn(state.url());
        lenient().when(request.path()).thenReturn(targetOf(state.url()));
        lenient().when(request.pathWithoutQuery()).thenReturn(pathOf(state.url()));
        lenient().when(request.query()).thenReturn(queryOf(state.url()));
        return request;
    }

    private static String targetOf(String url) {
        String query = queryOf(url);
        return query.isEmpty() ? pathOf(url) : pathOf(url) + "?" + query;
    }

    private static String queryOf(String url) {
        try {
            String query = java.net.URI.create(url).getRawQuery();
            return query != null ? query : "";
        } catch (IllegalArgumentException ignored) {
            return "";
        }
    }

    private static String pathOf(String url) {
        try {
            String path = java.net.URI.create(url).getRawPath();
            return path != null ? path : "/";
        } catch (IllegalArgumentException ignored) {
            return "/";
        }
    }

    private static HttpResponse buildHttpResponseMock(String raw) {
        String body = bodyOf(raw);
        return buildHttpResponseMock(raw, body, body.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                raw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static HttpResponse buildHttpResponseMock(byte[] raw) {
        String latin1 = new String(raw, java.nio.charset.StandardCharsets.ISO_8859_1);
        String body = bodyOf(latin1);
        return buildHttpResponseMock(latin1, body, body.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1), raw);
    }

    private static String bodyOf(String raw) {
        String[] parts = raw.split("\r\n\r\n", 2);
        return parts.length > 1 ? parts[1] : "";
    }

    private static HttpResponse buildHttpResponseMock(String raw, String body, byte[] rawBodyBytes, byte[] rawBytes) {
        HttpResponse response = mock(HttpResponse.class, withSettings().stubOnly());
        // Best-effort raw parse so the synthesised response satisfies T8's filters.
        String headerBlock = raw.split("\r\n\r\n", 2)[0];
        String[] lines = headerBlock.split("\r\n");
        short status = parseStatus(lines.length > 0 ? lines[0] : "");
        java.util.Map<String, String> headers = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        // Preserve duplicate header names (e.g. multiple Set-Cookie) as an ordered list so
        // callers that read headers() see every value, not just the last under each name.
        java.util.List<HttpHeader> headerList = new java.util.ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                String name = lines[i].substring(0, colon).trim();
                String value = lines[i].substring(colon + 1).trim();
                headers.putIfAbsent(name, value);
                headerList.add(buildHeaderMock(name, value));
            }
        }
        lenient().when(response.statusCode()).thenReturn(status);
        lenient().when(response.httpVersion()).thenReturn(lines.length > 0 ? lines[0].split(" ", 2)[0] : "");
        lenient().when(response.toByteArray()).thenAnswer(inv -> ByteArray.byteArray(rawBytes));
        lenient().when(response.bodyToString()).thenReturn(body);
        ByteArray bodyBytes = ByteArray.byteArray(rawBodyBytes);
        lenient().when(response.body()).thenReturn(bodyBytes);
        lenient().when(response.headerValue(anyString()))
                .thenAnswer(inv -> headers.get((String) inv.getArgument(0)));
        lenient().when(response.headers()).thenReturn(headerList);
        lenient().when(response.hasHeader(anyString())).thenAnswer(inv -> headers.containsKey((String) inv.getArgument(0)));
        lenient().when(response.withRemovedHeaders(anyList())).thenAnswer(inv -> {
            java.util.Set<String> removed = new java.util.TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            ((java.util.List<HttpHeader>) inv.getArgument(0)).forEach(header -> removed.add(header.name()));
            String kept = java.util.Arrays.stream(lines).skip(1)
                    .filter(line -> !removed.contains(line.split(":", 2)[0].trim()))
                    .map(line -> line + "\r\n").collect(java.util.stream.Collectors.joining());
            String rest = raw.contains("\r\n\r\n") ? raw.split("\r\n\r\n", 2)[1] : "";
            return buildHttpResponseMock(lines[0] + "\r\n" + kept + "\r\n" + rest);
        });
        return response;
    }

    private static short parseStatus(String statusLine) {
        try {
            String[] tokens = statusLine.split(" ");
            return tokens.length >= 2 ? Short.parseShort(tokens[1]) : 200;
        } catch (NumberFormatException ignored) {
            return 200;
        }
    }

    private static HttpService buildHttpServiceMock(String url) {
        java.net.URI uri = java.net.URI.create(url);
        boolean secure = "https".equalsIgnoreCase(uri.getScheme());
        int port = uri.getPort() != -1 ? uri.getPort() : (secure ? 443 : 80);
        HttpService service = mock(HttpService.class);
        lenient().when(service.host()).thenReturn(uri.getHost());
        lenient().when(service.port()).thenReturn(port);
        lenient().when(service.secure()).thenReturn(secure);
        return service;
    }

    private static void installHttpHandlerStubs(MontoyaObjectFactory factory) {
        lenient().when(factory.requestResult(any(HttpRequest.class)))
                .thenAnswer(invocation -> {
                    HttpRequest req = invocation.getArgument(0);
                    RequestToBeSentAction action = mock(RequestToBeSentAction.class);
                    lenient().when(action.request()).thenReturn(req);
                    return action;
                });

        lenient().when(factory.requestResult(any(burp.api.montoya.http.handler.RequestAction.class),
                        nullable(HttpRequest.class), any(HttpResponse.class), nullable(burp.api.montoya.core.Annotations.class)))
                .thenAnswer(invocation -> new SpoofedRequestAction(invocation.getArgument(0),
                        invocation.getArgument(1), invocation.getArgument(2), invocation.getArgument(3)));

        lenient().when(factory.responseResult(any(HttpResponse.class)))
                .thenAnswer(invocation -> {
                    HttpResponse resp = invocation.getArgument(0);
                    ResponseReceivedAction action = mock(ResponseReceivedAction.class);
                    lenient().when(action.response()).thenReturn(resp);
                    return action;
                });
    }

    private static void installAuditInsertionPointStub(MontoyaObjectFactory factory) {
        lenient().when(factory.auditInsertionPoint(anyString(), any(HttpRequest.class), anyInt(), anyInt()))
                .thenAnswer(invocation -> {
                    String name = invocation.getArgument(0);
                    int start = invocation.getArgument(2);
                    int end = invocation.getArgument(3);
                    AuditInsertionPoint point = mock(AuditInsertionPoint.class);
                    lenient().when(point.name()).thenReturn(name);
                    lenient().when(point.baseValue()).thenReturn(start + ":" + end);
                    return point;
                });
    }

    private static void installAuditConfigurationStub(MontoyaObjectFactory factory) {
        lenient().when(factory.auditConfiguration(any(BuiltInAuditConfiguration.class)))
                .thenReturn(mock(AuditConfiguration.class));
    }

    private static void installRangeStub(MontoyaObjectFactory factory) {
        lenient().when(factory.range(anyInt(), anyInt())).thenAnswer(invocation -> {
            int start = invocation.getArgument(0);
            int end = invocation.getArgument(1);
            Range range = mock(Range.class);
            lenient().when(range.startIndexInclusive()).thenReturn(start);
            lenient().when(range.endIndexExclusive()).thenReturn(end);
            return range;
        });
    }

    private static void installByteArrayStub(MontoyaObjectFactory factory) {
        lenient().when(factory.byteArray(anyString())).thenAnswer(invocation -> {
            String value = invocation.getArgument(0);
            return byteArrayMock(value, value.length(), value.getBytes());
        });

        lenient().when(factory.byteArray(any(byte[].class))).thenAnswer(invocation -> {
            byte[] data = (byte[]) invocation.getRawArguments()[0];
            byte[] safe = data != null ? data : new byte[0];
            return byteArrayMock(new String(safe), safe.length, safe);
        });
    }

    private static ByteArray byteArrayMock(String text, int length, byte[] bytes) {
        ByteArray byteArray = textRenderingMock(ByteArray.class, text);
        lenient().when(byteArray.length()).thenReturn(length);
        lenient().when(byteArray.getBytes()).thenReturn(bytes);
        return byteArray;
    }

    private static HttpHeader buildHeaderMock(String name, String value) {
        HttpHeader header = textRenderingMock(HttpHeader.class, name + ": " + value);
        lenient().when(header.name()).thenReturn(name);
        lenient().when(header.value()).thenReturn(value);
        return header;
    }

    private static <T> T textRenderingMock(Class<T> type, String text) {
        return mock(type, withSettings().stubOnly().defaultAnswer(invocation ->
                invocation.getMethod().getName().equals("toString") && invocation.getArguments().length == 0
                        ? text
                        : RETURNS_DEFAULTS.answer(invocation)));
    }

    @SuppressWarnings("unchecked")
    private static AuditIssue createMockIssue(String name,
                                               String detail,
                                               String remediation,
                                               String baseUrl,
                                               AuditIssueSeverity severity,
                                               AuditIssueConfidence confidence,
                                               String background,
                                               String remediationBackground,
                                               AuditIssueSeverity typicalSeverity,
                                               Object requestResponses) {
        AuditIssue issue = mock(AuditIssue.class);
        lenient().when(issue.name()).thenReturn(name);
        lenient().when(issue.detail()).thenReturn(detail);
        lenient().when(issue.remediation()).thenReturn(remediation);
        lenient().when(issue.baseUrl()).thenReturn(baseUrl);
        lenient().when(issue.severity()).thenReturn(severity);
        lenient().when(issue.confidence()).thenReturn(confidence);
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        lenient().when(definition.background()).thenReturn(background);
        lenient().when(definition.remediation()).thenReturn(remediationBackground);
        lenient().when(definition.typicalSeverity()).thenReturn(typicalSeverity);
        lenient().when(issue.definition()).thenReturn(definition);
        List<HttpRequestResponse> evidence = requestResponses instanceof List<?> list
                ? (List<HttpRequestResponse>) list
                : List.of();
        lenient().when(issue.requestResponses()).thenReturn(evidence);
        return issue;
    }
}
