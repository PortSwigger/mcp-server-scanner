package com.mcpscanner.testutil;

import burp.api.montoya.core.ByteArray;
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
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

public final class MontoyaTestFactory {

    private MontoyaTestFactory() {}

    public static void install() {
        MontoyaObjectFactory factory = ObjectFactoryLocator.FACTORY;
        if (factory == null) {
            factory = mock(MontoyaObjectFactory.class);
            ObjectFactoryLocator.FACTORY = factory;
        }

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
    }

    private static void installRequestOptionsStub(MontoyaObjectFactory factory) {
        lenient().when(factory.requestOptions()).thenAnswer(invocation -> {
            burp.api.montoya.http.RequestOptions options =
                    mock(burp.api.montoya.http.RequestOptions.class);
            lenient().when(options.withRedirectionMode(any())).thenReturn(options);
            lenient().when(options.withHttpMode(any())).thenReturn(options);
            lenient().when(options.withConnectionId(anyString())).thenReturn(options);
            lenient().when(options.withUpstreamTLSVerification()).thenReturn(options);
            lenient().when(options.withServerNameIndicator(anyString())).thenReturn(options);
            lenient().when(options.withResponseTimeout(anyLong())).thenReturn(options);
            return options;
        });
    }

    private static void installHttpRequestResponseStub(MontoyaObjectFactory factory) {
        lenient().when(factory.httpRequestResponse(any(HttpRequest.class), nullable(HttpResponse.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    HttpResponse response = invocation.getArgument(1);
                    HttpRequestResponse rr = mock(HttpRequestResponse.class);
                    lenient().when(rr.request()).thenReturn(request);
                    lenient().when(rr.response()).thenReturn(response);
                    return rr;
                });
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
                invocation.getArgument(4),
                invocation.getArgument(5),
                invocation.getArgument(6),
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
                invocation.getArgument(4),
                invocation.getArgument(5),
                invocation.getArgument(6),
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
            ByteArray bytes = invocation.getArgument(0);
            HttpResponse response = mock(HttpResponse.class);
            lenient().when(response.body()).thenReturn(bytes);
            lenient().when(response.bodyToString())
                    .thenReturn(bytes != null ? bytes.toString() : "");
            return response;
        });
    }

    private static HttpRequest buildHttpRequestMock(String url) {
        HttpService service = buildHttpServiceMock(url);
        HttpRequest request = mock(HttpRequest.class);
        // Track state so tests can assert on the synthesised request: T8's classifier
        // reads method() / bodyToString() / headerValue("Content-Type"), so the mock has
        // to actually return whatever the builder chain set.
        java.util.concurrent.atomic.AtomicReference<String> methodRef =
                new java.util.concurrent.atomic.AtomicReference<>("GET");
        java.util.concurrent.atomic.AtomicReference<String> bodyRef =
                new java.util.concurrent.atomic.AtomicReference<>("");
        java.util.Map<String, String> headers = new java.util.concurrent.ConcurrentHashMap<>();
        java.util.concurrent.atomic.AtomicReference<HttpService> serviceRef =
                new java.util.concurrent.atomic.AtomicReference<>(service);

        lenient().when(request.withMethod(anyString())).thenAnswer(inv -> {
            methodRef.set(inv.getArgument(0));
            return request;
        });
        lenient().when(request.withBody(anyString())).thenAnswer(inv -> {
            bodyRef.set(inv.getArgument(0));
            return request;
        });
        lenient().when(request.withService(any(HttpService.class))).thenAnswer(inv -> {
            serviceRef.set(inv.getArgument(0));
            return request;
        });
        lenient().when(request.withAddedHeader(anyString(), anyString())).thenAnswer(inv -> {
            headers.put(inv.getArgument(0), inv.getArgument(1));
            return request;
        });
        lenient().when(request.withHeader(anyString(), anyString())).thenAnswer(inv -> {
            headers.put(inv.getArgument(0), inv.getArgument(1));
            return request;
        });
        lenient().when(request.withRemovedHeaders(anyList())).thenAnswer(inv -> {
            List<?> toRemove = inv.getArgument(0);
            for (Object h : toRemove) {
                if (h instanceof HttpHeader hh) {
                    headers.remove(hh.name());
                }
            }
            return request;
        });
        lenient().when(request.method()).thenAnswer(inv -> methodRef.get());
        lenient().when(request.bodyToString()).thenAnswer(inv -> bodyRef.get());
        lenient().when(request.headerValue(anyString()))
                .thenAnswer(inv -> headers.get((String) inv.getArgument(0)));
        lenient().when(request.httpService()).thenAnswer(inv -> serviceRef.get());
        lenient().when(request.headers()).thenAnswer(inv ->
                headers.entrySet().stream()
                        .map(e -> buildHeaderMock(e.getKey(), e.getValue()))
                        .toList());
        // Expose the full URL and path so RecordingRealHttp.resolveUrl() can route requests
        // to the correct endpoint (e.g. /.well-known/ discovery URLs) rather than
        // always falling back to /mcp.
        java.net.URI parsedUri;
        try {
            parsedUri = java.net.URI.create(url);
        } catch (IllegalArgumentException ignored) {
            parsedUri = null;
        }
        java.net.URI finalParsedUri = parsedUri;
        lenient().when(request.url()).thenReturn(url);
        lenient().when(request.path()).thenReturn(
                finalParsedUri != null && finalParsedUri.getRawPath() != null
                        ? finalParsedUri.getRawPath()
                        : "/");
        return request;
    }

    private static HttpResponse buildHttpResponseMock(String raw) {
        HttpResponse response = mock(HttpResponse.class);
        // Best-effort raw parse so the synthesised response satisfies T8's filters.
        String[] parts = raw.split("\r\n\r\n", 2);
        String body = parts.length > 1 ? parts[1] : "";
        String headerBlock = parts[0];
        String[] lines = headerBlock.split("\r\n");
        short status = parseStatus(lines.length > 0 ? lines[0] : "");
        java.util.Map<String, String> headers = new java.util.LinkedHashMap<>();
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
        lenient().when(response.bodyToString()).thenReturn(body);
        lenient().when(response.headerValue(anyString()))
                .thenAnswer(inv -> headers.get((String) inv.getArgument(0)));
        lenient().when(response.headers()).thenReturn(headerList);
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
            ByteArray byteArray = mock(ByteArray.class);
            lenient().when(byteArray.toString()).thenReturn(value);
            lenient().when(byteArray.length()).thenReturn(value.length());
            lenient().when(byteArray.getBytes()).thenReturn(value.getBytes());
            return byteArray;
        });

        lenient().when(factory.byteArray(any(byte[].class))).thenAnswer(invocation -> {
            byte[] data = (byte[]) invocation.getRawArguments()[0];
            byte[] safe = data != null ? data : new byte[0];
            ByteArray byteArray = mock(ByteArray.class);
            lenient().when(byteArray.toString()).thenReturn(new String(safe));
            lenient().when(byteArray.length()).thenReturn(safe.length);
            lenient().when(byteArray.getBytes()).thenReturn(safe);
            return byteArray;
        });
    }

    private static HttpHeader buildHeaderMock(String name, String value) {
        HttpHeader header = mock(HttpHeader.class);
        lenient().when(header.name()).thenReturn(name);
        lenient().when(header.value()).thenReturn(value);
        lenient().when(header.toString()).thenReturn(name + ": " + value);
        return header;
    }

    @SuppressWarnings("unchecked")
    private static AuditIssue createMockIssue(String name,
                                               String detail,
                                               String remediation,
                                               AuditIssueSeverity severity,
                                               AuditIssueConfidence confidence,
                                               String background,
                                               Object requestResponses) {
        AuditIssue issue = mock(AuditIssue.class);
        lenient().when(issue.name()).thenReturn(name);
        lenient().when(issue.detail()).thenReturn(detail);
        lenient().when(issue.remediation()).thenReturn(remediation);
        lenient().when(issue.severity()).thenReturn(severity);
        lenient().when(issue.confidence()).thenReturn(confidence);
        AuditIssueDefinition definition = mock(AuditIssueDefinition.class);
        lenient().when(definition.background()).thenReturn(background);
        lenient().when(issue.definition()).thenReturn(definition);
        List<HttpRequestResponse> evidence = requestResponses instanceof List<?> list
                ? (List<HttpRequestResponse>) list
                : List.of();
        lenient().when(issue.requestResponses()).thenReturn(evidence);
        return issue;
    }
}
