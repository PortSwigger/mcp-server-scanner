package com.mcpscanner.checks.catalog.outboundrequest;

import java.util.Optional;

enum ProbeForm {

    ABSOLUTE_URL("absolute URL") {
        @Override
        Optional<String> render(String host, String baseValue) {
            return Optional.of("http://" + host);
        }
    },
    BARE_HOST("bare host") {
        @Override
        Optional<String> render(String host, String baseValue) {
            return Optional.of(host);
        }
    },
    HOST_SUFFIX("original host with the payload host appended") {
        @Override
        Optional<String> render(String host, String baseValue) {
            return BaseUrl.parse(baseValue).map(base -> base.withHostSuffix(host));
        }
    },
    USERINFO_HOST("original host as userinfo before the payload host") {
        @Override
        Optional<String> render(String host, String baseValue) {
            return BaseUrl.parse(baseValue).map(base -> base.withUserInfoHost(host));
        }
    },
    LONG_FLAG_SERVER("long flag --server") {
        @Override
        Optional<String> render(String host, String baseValue) {
            return Optional.of("--server=http://" + host + "/");
        }
    },
    LONG_FLAG_URL("long flag --url") {
        @Override
        Optional<String> render(String host, String baseValue) {
            return Optional.of("--url=http://" + host + "/");
        }
    },
    ATTACHED_SHORT_FLAG("attached short flag -s") {
        @Override
        Optional<String> render(String host, String baseValue) {
            return Optional.of("-shttp://" + host + "/");
        }
    };

    private final String label;

    ProbeForm(String label) {
        this.label = label;
    }

    String label() {
        return label;
    }

    abstract Optional<String> render(String host, String baseValue);
}
