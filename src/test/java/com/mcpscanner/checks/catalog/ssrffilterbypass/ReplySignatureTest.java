package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ReplySignatureTest {

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void ignoresTheReplyIdTheEchoedHostAndThePort() {
        String first = signature(1, "blocked http://127.0.0.1:1/ (127.0.0.1)", "127.0.0.1", 1);
        String second = signature(2, "blocked http://127.0.0.1:8191/ (127.0.0.1)", "127.0.0.1", 8191);

        assertThat(first).isEqualTo(second);
    }

    @Test
    void treatsAnEchoOfTheCanonicalLoopbackAddressLikeAnEchoOfTheSpellingSent() {
        String dotted = signature(1, "Failed to fetch http://127.0.0.1:58005/robots.txt", "127.0.0.1", 58005);
        String hexadecimal = signature(1, "Failed to fetch http://127.0.0.1:58005/robots.txt", "0x7f000001", 58005);
        String mapped = signature(1, "Failed to fetch http://[::ffff:7f00:1]:58005/robots.txt", "[::ffff:7f00:1]",
                58005);
        String javaLongForm = signature(1, "Failed to fetch http://[0:0:0:0:0:ffff:7f00:1]:58005/robots.txt",
                "[::ffff:7f00:1]", 58005);

        assertThat(hexadecimal).isEqualTo(dotted);
        assertThat(mapped).isEqualTo(dotted);
        assertThat(javaLongForm).isEqualTo(dotted);
    }

    @Test
    void keepsOtherDifferences() {
        assertThat(signature(1, "blocked", "127.0.0.1", 1))
                .isNotEqualTo(signature(1, "connect refused", "[::ffff:7f00:1]", 1));
    }

    @Test
    void neutralisesThePortOnlyWhereItFollowsTheHost() {
        assertThat(signature(1, "retry 1 of :1 at 127.0.0.1:1", "127.0.0.1", 1))
                .contains("retry 1 of :1 at §host:§port");
    }

    private static String signature(int id, String text, String host, int port) {
        return ReplySignature.of(HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                + "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\""
                + text + "\"}],\"isError\":true}}"), ProbeUrl.loopback(host, port));
    }
}
