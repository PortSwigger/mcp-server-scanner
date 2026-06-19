package com.mcpscanner.scan;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;
import com.mcpscanner.scan.ArgumentValueLocator.ValueKind;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JsonValueInsertionPointTest {

    private static final int BODY_OFFSET = 200;

    @Mock
    private HttpRequest baseRequest;

    @Mock
    private HttpRequest modifiedRequest;

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @BeforeEach
    void setUpRequestStubs() {
        lenient().when(baseRequest.withBody(anyString())).thenReturn(modifiedRequest);
    }

    @Test
    void returnsParameterName() {
        JsonValueInsertionPoint point = numberInsertionPoint();

        assertThat(point.name()).isEqualTo("MCP arg: count");
    }

    @Test
    void returnsBaseValue() {
        JsonValueInsertionPoint point = numberInsertionPoint();

        assertThat(point.baseValue()).isEqualTo("42");
    }

    @Test
    void returnsParamJsonType() {
        JsonValueInsertionPoint point = numberInsertionPoint();

        assertThat(point.type()).isEqualTo(AuditInsertionPointType.PARAM_JSON);
    }

    @Test
    void numberValueAcceptsValidJsonNumberAsRaw() {
        JsonValueInsertionPoint point = numberInsertionPoint();

        point.buildHttpRequestWithPayload(ByteArray.byteArray("99999"));

        verify(baseRequest).withBody("{\"arguments\":{\"count\":99999},\"name\":\"calc\"}");
    }

    @Test
    void numberValueWrapsBooleanPayloadAsJsonString() {
        JsonValueInsertionPoint point = numberInsertionPoint();

        point.buildHttpRequestWithPayload(ByteArray.byteArray("not-a-number"));

        verify(baseRequest).withBody("{\"arguments\":{\"count\":\"not-a-number\"},\"name\":\"calc\"}");
    }

    @Test
    void numberValueWrapsNonNumericTextAsJsonString() {
        JsonValueInsertionPoint point = numberInsertionPoint();

        point.buildHttpRequestWithPayload(ByteArray.byteArray("false"));

        verify(baseRequest).withBody("{\"arguments\":{\"count\":\"false\"},\"name\":\"calc\"}");
    }

    @Test
    void booleanValueAcceptsTrueLiteral() {
        JsonValueInsertionPoint point = booleanInsertionPoint();

        point.buildHttpRequestWithPayload(ByteArray.byteArray("true"));

        verify(baseRequest).withBody("{\"arguments\":{\"flag\":true},\"name\":\"calc\"}");
    }

    @Test
    void booleanValueAcceptsFalseLiteral() {
        JsonValueInsertionPoint point = booleanInsertionPoint();

        point.buildHttpRequestWithPayload(ByteArray.byteArray("false"));

        verify(baseRequest).withBody("{\"arguments\":{\"flag\":false},\"name\":\"calc\"}");
    }

    @Test
    void booleanValueWrapsArbitraryWordAsJsonString() {
        JsonValueInsertionPoint point = booleanInsertionPoint();

        point.buildHttpRequestWithPayload(ByteArray.byteArray("maybe"));

        verify(baseRequest).withBody("{\"arguments\":{\"flag\":\"maybe\"},\"name\":\"calc\"}");
    }

    @Test
    void nullValueAcceptsNullLiteral() {
        JsonValueInsertionPoint point = nullInsertionPoint();

        point.buildHttpRequestWithPayload(ByteArray.byteArray("null"));

        verify(baseRequest).withBody("{\"arguments\":{\"opt\":null},\"name\":\"calc\"}");
    }

    @Test
    void nullValueWrapsArbitraryTextAsJsonString() {
        JsonValueInsertionPoint point = nullInsertionPoint();

        point.buildHttpRequestWithPayload(ByteArray.byteArray("nope"));

        verify(baseRequest).withBody("{\"arguments\":{\"opt\":\"nope\"},\"name\":\"calc\"}");
    }

    @Test
    void stringValueAlwaysWrapsPayloadAsJsonString() {
        JsonValueInsertionPoint point = stringInsertionPoint();

        point.buildHttpRequestWithPayload(ByteArray.byteArray("hello"));

        verify(baseRequest).withBody("{\"arguments\":{\"msg\":\"hello\"},\"name\":\"calc\"}");
    }

    @Test
    void stringValueEscapesEmbeddedDoubleQuote() {
        JsonValueInsertionPoint point = stringInsertionPoint();

        point.buildHttpRequestWithPayload(ByteArray.byteArray("injected\"value"));

        verify(baseRequest).withBody("{\"arguments\":{\"msg\":\"injected\\\"value\"},\"name\":\"calc\"}");
    }

    @Test
    void stringValueEscapesLiteralNewlineByte() {
        JsonValueInsertionPoint point = stringInsertionPoint();

        point.buildHttpRequestWithPayload(ByteArray.byteArray("with\nnewline"));

        verify(baseRequest).withBody("{\"arguments\":{\"msg\":\"with\\nnewline\"},\"name\":\"calc\"}");
    }

    @Test
    void stringValueEscapesBackslash() {
        JsonValueInsertionPoint point = stringInsertionPoint();

        point.buildHttpRequestWithPayload(ByteArray.byteArray("path\\to\\file"));

        verify(baseRequest).withBody("{\"arguments\":{\"msg\":\"path\\\\to\\\\file\"},\"name\":\"calc\"}");
    }

    @Test
    void issueHighlightsCoversReplacedRangeForRawNumber() {
        JsonValueInsertionPoint point = numberInsertionPoint();
        when(baseRequest.bodyOffset()).thenReturn(BODY_OFFSET);

        List<Range> highlights = point.issueHighlights(ByteArray.byteArray("99999"));

        assertThat(highlights).hasSize(1);
        Range range = highlights.get(0);
        int valueStart = numberBody().indexOf("42");
        assertThat(range.startIndexInclusive()).isEqualTo(BODY_OFFSET + valueStart);
        assertThat(range.endIndexExclusive()).isEqualTo(BODY_OFFSET + valueStart + "99999".length());
    }

    @Test
    void issueHighlightsCoversReplacedRangeForWrappedString() {
        JsonValueInsertionPoint point = stringInsertionPoint();
        when(baseRequest.bodyOffset()).thenReturn(BODY_OFFSET);

        List<Range> highlights = point.issueHighlights(ByteArray.byteArray("<script>"));

        assertThat(highlights).hasSize(1);
        int valueStart = stringBody().indexOf("\"hello\"");
        int wrappedLength = "\"<script>\"".length();
        assertThat(highlights.get(0).startIndexInclusive()).isEqualTo(BODY_OFFSET + valueStart);
        assertThat(highlights.get(0).endIndexExclusive()).isEqualTo(BODY_OFFSET + valueStart + wrappedLength);
    }

    private JsonValueInsertionPoint numberInsertionPoint() {
        String body = numberBody();
        lenient().when(baseRequest.bodyToString()).thenReturn(body);
        int start = body.indexOf("42");
        int end = start + "42".length();
        return new JsonValueInsertionPoint("count", baseRequest, "42", start, end, ValueKind.NUMBER);
    }

    private JsonValueInsertionPoint booleanInsertionPoint() {
        String body = "{\"arguments\":{\"flag\":true},\"name\":\"calc\"}";
        lenient().when(baseRequest.bodyToString()).thenReturn(body);
        int start = body.indexOf("true");
        int end = start + "true".length();
        return new JsonValueInsertionPoint("flag", baseRequest, "true", start, end, ValueKind.BOOLEAN);
    }

    private JsonValueInsertionPoint nullInsertionPoint() {
        String body = "{\"arguments\":{\"opt\":null},\"name\":\"calc\"}";
        lenient().when(baseRequest.bodyToString()).thenReturn(body);
        int start = body.indexOf("null");
        int end = start + "null".length();
        return new JsonValueInsertionPoint("opt", baseRequest, "null", start, end, ValueKind.NULL);
    }

    private JsonValueInsertionPoint stringInsertionPoint() {
        String body = stringBody();
        lenient().when(baseRequest.bodyToString()).thenReturn(body);
        int start = body.indexOf("\"hello\"");
        int end = start + "\"hello\"".length();
        return new JsonValueInsertionPoint("msg", baseRequest, "\"hello\"", start, end, ValueKind.STRING);
    }

    private String numberBody() {
        return "{\"arguments\":{\"count\":42},\"name\":\"calc\"}";
    }

    private String stringBody() {
        return "{\"arguments\":{\"msg\":\"hello\"},\"name\":\"calc\"}";
    }
}
