package com.mcpscanner.checks;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class FileSignatureTest {

    @Test
    void passwd_matchesRootPlusTwoUserLines() {
        String content = "root:x:0:0:root:/root:/bin/bash\n"
                + "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                + "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n";

        assertThat(FileSignature.PASSWD.matches(content)).isTrue();
    }

    @Test
    void passwd_doesNotMatchRootLineAlone() {
        assertThat(FileSignature.PASSWD.matches("root:x:0:0:root:/root:/bin/bash\n")).isFalse();
    }

    @Test
    void passwd_doesNotMatchRootLinePlusExactlyOneUserLine() {
        // The root line is passwd-shaped and would otherwise be counted as a "user line", silently
        // degrading the corroboration to "root + 1 user". Excluding the root line keeps the bar at
        // two GENUINE non-root user entries.
        String content = "root:x:0:0:root:/root:/bin/bash\n"
                + "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n";

        assertThat(FileSignature.PASSWD.matches(content)).isFalse();
    }

    @Test
    void passwd_matchesRootPlusTwoDistinctUsers() {
        // The existing positive fixture shape (root + >=2 distinct users) must still match.
        String content = "root:x:0:0:root:/root:/bin/bash\n"
                + "nobody:x:65534:65534:nobody:/nonexistent:/bin/sh\n"
                + "mail:x:8:8:mail:/var/mail:/bin/sh\n";

        assertThat(FileSignature.PASSWD.matches(content)).isTrue();
    }

    @Test
    void passwd_matchesJsonWrappedContentWithLiteralNewlineEscapes() {
        // A server that returns the leaked file inside a JSON string envelope keeps /etc/passwd's
        // newlines as literal two-char \n escape sequences on ONE physical line; the multiline
        // anchors only see the unescaped view.
        String jsonWrapped = "{\"success\":true,\"content\":\""
                + "root:x:0:0:root:/root:/bin/bash\\n"
                + "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\n"
                + "bin:x:2:2:bin:/bin:/usr/sbin/nologin\\n\"}";

        assertThat(FileSignature.PASSWD.matches(jsonWrapped)).isTrue();
    }

    @Test
    void passwd_matchesDoubleEscapedJsonWrappedContent() {
        // A re-encoded / double-encoded envelope can carry the four-char \\n form.
        String doubleEscaped = "{\"content\":\""
                + "root:x:0:0:root:/root:/bin/bash\\\\n"
                + "nobody:x:65534:65534:nobody:/nonexistent:/bin/sh\\\\n"
                + "mail:x:8:8:mail:/var/mail:/bin/sh\\\\n\"}";

        assertThat(FileSignature.PASSWD.matches(doubleEscaped)).isTrue();
    }

    @Test
    void passwd_doesNotMatchJsonWrappedRootLineAlone() {
        // FP guard preserved across the unescaped view: a single root line with no further user
        // lines must still not match, even when JSON-wrapped.
        String jsonWrapped = "{\"success\":true,\"content\":\"root:x:0:0:root:/root:/bin/bash\\n\"}";

        assertThat(FileSignature.PASSWD.matches(jsonWrapped)).isFalse();
    }

    @Test
    void passwd_doesNotMatchPasswdFragmentsAcrossSeparateJsonFields() {
        // Each field is a benign isolated fragment; only by gluing them across fields could a
        // root + 2-user body be manufactured. JSON-aware per-leaf matching tests each in isolation,
        // so no single value carries the required corroboration -> no match.
        String multiField = "{\"r\":\"root:x:0:0:root:/root:/bin/bash\","
                + "\"u1\":\"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\","
                + "\"u2\":\"bin:x:2:2:bin:/bin:/usr/sbin/nologin\"}";

        assertThat(FileSignature.PASSWD.matches(multiField)).isFalse();
    }

    @Test
    void passwd_doesNotMatchSingleValueWithSameNonRootLineRepeated() {
        // root + the SAME non-root line twice is only ONE distinct user; the distinctness Set must
        // reject it rather than counting the duplicate as two entries.
        String jsonWrapped = "{\"content\":\""
                + "root:x:0:0:root:/root:/bin/bash\\n"
                + "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\n"
                + "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\n\"}";

        assertThat(FileSignature.PASSWD.matches(jsonWrapped)).isFalse();
    }

    @Test
    void hosts_doesNotMatchLocalhostFragmentsAcrossSeparateJsonFields() {
        // Two benign localhost-ish values in separate fields must NOT combine into a hosts match;
        // a global delimiter rewrite used to manufacture line-starts before every value here.
        String multiField = "{\"a\":\"127.0.0.1 localhost\",\"b\":\"::1 localhost\"}";

        assertThat(FileSignature.HOSTS.matches(multiField)).isFalse();
    }

    @Test
    void hosts_matchesJsonWrappedContentWithLiteralNewlineEscapes() {
        String jsonWrapped = "{\"content\":\"127.0.0.1 localhost\\n::1 localhost\\n\"}";

        assertThat(FileSignature.HOSTS.matches(jsonWrapped)).isTrue();
    }

    @Test
    void hosts_doesNotMatchJsonWrappedLocalhostLineAlone() {
        String jsonWrapped = "{\"content\":\"127.0.0.1 localhost\\n\"}";

        assertThat(FileSignature.HOSTS.matches(jsonWrapped)).isFalse();
    }

    @Test
    void hosts_matchesLocalhostPlusCorroboratingLine() {
        String content = "127.0.0.1 localhost\n::1 localhost\n";

        assertThat(FileSignature.HOSTS.matches(content)).isTrue();
    }

    @Test
    void hosts_matchesLocalhostPlusBroadcastLine() {
        String content = "127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n";

        assertThat(FileSignature.HOSTS.matches(content)).isTrue();
    }

    @Test
    void hosts_doesNotMatchLocalhostLineAlone() {
        // A benign diagnostic / log line echoing the canonical loopback entry must not match;
        // a real /etc/hosts file carries at least one further canonical entry.
        assertThat(FileSignature.HOSTS.matches("127.0.0.1 localhost\n")).isFalse();
    }

    @Test
    void winIni_matchesFontsMarker() {
        assertThat(FileSignature.WIN_INI.matches("; for 16-bit app support\n[fonts]\n")).isTrue();
    }

    @Test
    void winIni_doesNotMatchUnrelatedText() {
        assertThat(FileSignature.WIN_INI.matches("nothing here")).isFalse();
    }

    @Test
    void humanLabel_rendersPlainFileNamesNotEnumIdentifiers() {
        assertThat(FileSignature.PASSWD.humanLabel()).isEqualTo("Unix password file");
        assertThat(FileSignature.HOSTS.humanLabel()).isEqualTo("hosts file");
        assertThat(FileSignature.WIN_INI.humanLabel()).isEqualTo("Windows win.ini");
    }
}
