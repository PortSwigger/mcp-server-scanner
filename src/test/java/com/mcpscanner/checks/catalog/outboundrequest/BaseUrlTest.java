package com.mcpscanner.checks.catalog.outboundrequest;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BaseUrlTest {

    @Test
    void appendsTheAttackerHostToTheOriginalHostKeepingPathAndQuery() {
        assertThat(BaseUrl.parse("https://docs.apify.com/platform/actors?x=1").orElseThrow()
                .withHostSuffix("p1.oob.test")).isEqualTo("https://docs.apify.com.p1.oob.test/platform/actors?x=1");
    }

    @Test
    void placesTheOriginalHostAsUserinfoBeforeTheAttackerHost() {
        assertThat(BaseUrl.parse("HTTPS://docs.apify.com:8443").orElseThrow().withUserInfoHost("p1.oob.test"))
                .isEqualTo("https://docs.apify.com@p1.oob.test/");
    }

    @Test
    void acceptsOnlyHttpUrlsWithAHost() {
        assertThat(BaseUrl.parse("file:///etc/passwd")).isEmpty();
        assertThat(BaseUrl.parse("docs.apify.com")).isEmpty();
        assertThat(BaseUrl.parse("5")).isEmpty();
        assertThat(BaseUrl.parse("not a url")).isEmpty();
    }
}
