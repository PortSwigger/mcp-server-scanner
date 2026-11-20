package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

record ClientIdPrefix(String value) {

    private static final String UUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";
    private static final Pattern BARE_UUID = Pattern.compile(UUID);
    private static final Pattern UUID_TAIL = Pattern.compile("(.*[^-_.:])[-_.:]" + UUID);
    private static final Pattern RANDOM_TAIL = Pattern.compile("(.*[^-_.:])[-_.:][A-Za-z0-9]{8,}");

    static Optional<ClientIdPrefix> of(String clientId) {
        if (BARE_UUID.matcher(clientId).matches()) {
            return Optional.empty();
        }
        return prefix(UUID_TAIL.matcher(clientId)).or(() -> prefix(RANDOM_TAIL.matcher(clientId)));
    }

    boolean sharedBy(String clientId) {
        return of(clientId).filter(this::equals).isPresent();
    }

    @Override
    public String toString() {
        return value;
    }

    private static Optional<ClientIdPrefix> prefix(Matcher matcher) {
        return matcher.matches() ? Optional.of(new ClientIdPrefix(matcher.group(1))) : Optional.empty();
    }
}
