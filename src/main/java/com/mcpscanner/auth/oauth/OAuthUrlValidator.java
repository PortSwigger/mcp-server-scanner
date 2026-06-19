package com.mcpscanner.auth.oauth;

import com.mcpscanner.auth.oauth.safety.HostResolver;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

public class OAuthUrlValidator {

    public static final String CLASSIFICATION_MISSING_SCHEME_OR_HOST = "missing-scheme-or-host";
    public static final String CLASSIFICATION_INVALID_SCHEME = "invalid-scheme";
    public static final String CLASSIFICATION_HTTP_DOWNGRADE = "http-downgrade";
    public static final String CLASSIFICATION_PLAIN_HTTP_NON_LOOPBACK = "plain-http-non-loopback";
    public static final String CLASSIFICATION_INVALID_PORT = "invalid-port";
    public static final String CLASSIFICATION_LOOPBACK = "loopback";
    public static final String CLASSIFICATION_LINK_LOCAL = "link-local";
    public static final String CLASSIFICATION_CLOUD_METADATA = "cloud-metadata";
    public static final String CLASSIFICATION_PRIVATE = "private";
    public static final String CLASSIFICATION_MULTICAST = "multicast";
    public static final String CLASSIFICATION_UNSPECIFIED = "unspecified";
    public static final String CLASSIFICATION_UNRESOLVABLE = "unresolvable";
    public static final String CLASSIFICATION_CROSS_ORIGIN = "cross-origin";

    private static final Set<String> LOOPBACK_HOSTS = Set.of("127.0.0.1", "::1", "localhost");
    private static final String CLOUD_METADATA_HOST = "169.254.169.254";
    private static final String HTTPS_SCHEME = "https";
    private static final String HTTP_SCHEME = "http";

    private static final Set<String> CLASSIFICATIONS_TOLERATED_BY_VALIDATE = Set.of(CLASSIFICATION_LOOPBACK);

    public void validate(URI uri) {
        Optional<String> classification = classify(uri);
        if (classification.isPresent() && !CLASSIFICATIONS_TOLERATED_BY_VALIDATE.contains(classification.get())) {
            throw new OAuthException(toFailureMessage(classification.get(), uri));
        }
        if (uri != null && uri.getPort() == 0) {
            throw new OAuthException(toFailureMessage(CLASSIFICATION_INVALID_PORT, uri));
        }
    }

    public Optional<String> classify(URI uri) {
        if (uri == null) {
            return Optional.of(CLASSIFICATION_MISSING_SCHEME_OR_HOST);
        }
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (scheme == null || host == null || host.isBlank()) {
            return Optional.of(CLASSIFICATION_MISSING_SCHEME_OR_HOST);
        }
        if (!isSupportedScheme(scheme)) {
            return Optional.of(CLASSIFICATION_INVALID_SCHEME);
        }
        Optional<String> addressClassification = classifyHost(host);
        if (addressClassification.isPresent()) {
            return addressClassification;
        }
        if (isPlainHttp(scheme)) {
            return Optional.of(CLASSIFICATION_HTTP_DOWNGRADE);
        }
        if (uri.getPort() == 0) {
            return Optional.of(CLASSIFICATION_INVALID_PORT);
        }
        return Optional.empty();
    }

    /**
     * DNS-resolving classification used by {@code DefaultSuspiciousDestinationGate}. Resolves
     * the host and classifies every returned address, plus cross-origin relative to the
     * provided origin. Aggregates all suspicious codes into a single result; empty codes means
     * "clean, allow without prompting".
     *
     * <p>Distinguishes resolution outcomes:
     * <ul>
     *   <li>Timeout → {@link #CLASSIFICATION_UNRESOLVABLE} (hard block by the gate).</li>
     *   <li>UnknownHost (no records) → no UNRESOLVABLE code; leaves it to the HTTP layer
     *       to fail loudly. Avoids spurious denies for offline/CI environments where
     *       arbitrary hostnames don't resolve.</li>
     * </ul>
     *
     * @param uri        the destination URL to classify.
     * @param resolver   pluggable host resolver — injectable so callers can avoid real DNS.
     * @param mcpOrigin  the configured MCP endpoint origin used to detect cross-origin
     *                   destinations. Pass {@code null} to skip the cross-origin check.
     */
    public Classification classifyAll(URI uri, HostResolver resolver, URI mcpOrigin) {
        if (uri == null) {
            return Classification.of(CLASSIFICATION_MISSING_SCHEME_OR_HOST);
        }
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (scheme == null || host == null || host.isBlank()) {
            return Classification.of(CLASSIFICATION_MISSING_SCHEME_OR_HOST);
        }
        if (!isSupportedScheme(scheme)) {
            return Classification.of(CLASSIFICATION_INVALID_SCHEME);
        }
        if (uri.getPort() == 0) {
            return Classification.of(CLASSIFICATION_INVALID_PORT);
        }
        LinkedHashSet<String> codes = new LinkedHashSet<>();
        addCrossOriginIfApplicable(codes, uri, mcpOrigin);
        ResolutionOutcome resolution = resolveAddresses(host, resolver);
        if (resolution.timedOut()) {
            codes.add(CLASSIFICATION_UNRESOLVABLE);
            return new Classification(new ArrayList<>(codes), null);
        }
        for (InetAddress address : resolution.addresses()) {
            classifyAddress(address, host).ifPresent(codes::add);
        }
        if (isPlainHttp(scheme) && !codesIncludeLoopback(codes) && !isLoopbackHost(host)) {
            codes.add(CLASSIFICATION_PLAIN_HTTP_NON_LOOPBACK);
        }
        return new Classification(new ArrayList<>(codes), firstAddressLiteral(resolution.addresses()));
    }

    private boolean isSupportedScheme(String scheme) {
        return HTTPS_SCHEME.equalsIgnoreCase(scheme) || HTTP_SCHEME.equalsIgnoreCase(scheme);
    }

    private boolean isPlainHttp(String scheme) {
        return HTTP_SCHEME.equalsIgnoreCase(scheme);
    }

    private Optional<String> classifyHost(String host) {
        if (isLoopbackHost(host)) {
            return Optional.of(CLASSIFICATION_LOOPBACK);
        }
        String stripped = stripBrackets(host);
        if (!isIpLiteral(stripped)) {
            return Optional.empty();
        }
        InetAddress address;
        try {
            address = InetAddress.getByName(stripped);
        } catch (UnknownHostException e) {
            return Optional.of(CLASSIFICATION_UNRESOLVABLE);
        }
        return classifyAddress(address, stripped);
    }

    private Optional<String> classifyAddress(InetAddress address, String literalHost) {
        if (CLOUD_METADATA_HOST.equals(literalHost) || CLOUD_METADATA_HOST.equals(address.getHostAddress())) {
            return Optional.of(CLASSIFICATION_CLOUD_METADATA);
        }
        if (address.isLoopbackAddress()) {
            return Optional.of(CLASSIFICATION_LOOPBACK);
        }
        if (address.isLinkLocalAddress()) {
            return Optional.of(CLASSIFICATION_LINK_LOCAL);
        }
        if (address.isSiteLocalAddress() || isIpv4PrivateRange(address) || isIpv6UniqueLocal(address)) {
            return Optional.of(CLASSIFICATION_PRIVATE);
        }
        if (address.isMulticastAddress()) {
            return Optional.of(CLASSIFICATION_MULTICAST);
        }
        if (address.isAnyLocalAddress()) {
            return Optional.of(CLASSIFICATION_UNSPECIFIED);
        }
        return Optional.empty();
    }

    private void addCrossOriginIfApplicable(LinkedHashSet<String> codes, URI uri, URI mcpOrigin) {
        if (mcpOrigin == null) {
            return;
        }
        String destHost = uri.getHost();
        String originHost = mcpOrigin.getHost();
        if (destHost == null || originHost == null) {
            return;
        }
        if (!destHost.equalsIgnoreCase(originHost)) {
            codes.add(CLASSIFICATION_CROSS_ORIGIN);
        }
    }

    private ResolutionOutcome resolveAddresses(String host, HostResolver resolver) {
        String stripped = stripBrackets(host);
        if (isIpLiteral(stripped)) {
            try {
                return ResolutionOutcome.of(List.of(InetAddress.getByName(stripped)));
            } catch (UnknownHostException e) {
                return ResolutionOutcome.empty();
            }
        }
        if (isLoopbackHost(stripped)) {
            try {
                return ResolutionOutcome.of(List.of(InetAddress.getByName("127.0.0.1")));
            } catch (UnknownHostException e) {
                return ResolutionOutcome.empty();
            }
        }
        if (resolver == null) {
            return ResolutionOutcome.empty();
        }
        try {
            return ResolutionOutcome.of(resolver.resolve(stripped));
        } catch (HostResolver.ResolutionTimeoutException e) {
            return ResolutionOutcome.timeout();
        }
    }

    private static boolean codesIncludeLoopback(LinkedHashSet<String> codes) {
        return codes.contains(CLASSIFICATION_LOOPBACK);
    }

    private static String firstAddressLiteral(List<InetAddress> addresses) {
        return addresses.isEmpty() ? null : addresses.get(0).getHostAddress();
    }

    private boolean isLoopbackHost(String host) {
        return LOOPBACK_HOSTS.contains(stripBrackets(host).toLowerCase(Locale.ROOT));
    }

    private String stripBrackets(String host) {
        if (host.startsWith("[") && host.endsWith("]")) {
            return host.substring(1, host.length() - 1);
        }
        return host;
    }

    private boolean isIpLiteral(String host) {
        return host.indexOf(':') >= 0 || host.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    private boolean isIpv4PrivateRange(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length != 4) {
            return false;
        }
        int b0 = bytes[0] & 0xff;
        int b1 = bytes[1] & 0xff;
        if (b0 == 10) {
            return true;
        }
        if (b0 == 172 && b1 >= 16 && b1 <= 31) {
            return true;
        }
        return b0 == 192 && b1 == 168;
    }

    private boolean isIpv6UniqueLocal(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length != 16) {
            return false;
        }
        return (bytes[0] & 0xfe) == 0xfc;
    }

    private static String toFailureMessage(String classification, URI uri) {
        return switch (classification) {
            case CLASSIFICATION_MISSING_SCHEME_OR_HOST ->
                    uri == null ? "URL must not be null" : "URL must have an explicit scheme and host: " + uri;
            case CLASSIFICATION_INVALID_SCHEME, CLASSIFICATION_HTTP_DOWNGRADE ->
                    "URL must use https (http allowed only for loopback): " + uri;
            case CLASSIFICATION_INVALID_PORT -> "URL has invalid port: " + uri;
            case CLASSIFICATION_LOOPBACK -> "URL resolves to a loopback address: " + uri;
            case CLASSIFICATION_LINK_LOCAL, CLASSIFICATION_CLOUD_METADATA ->
                    "URL resolves to a link-local address: " + uri;
            case CLASSIFICATION_PRIVATE -> "URL resolves to a private address: " + uri;
            case CLASSIFICATION_MULTICAST -> "URL resolves to a multicast address: " + uri;
            case CLASSIFICATION_UNSPECIFIED -> "URL resolves to an unspecified address: " + uri;
            case CLASSIFICATION_UNRESOLVABLE -> "URL host could not be resolved: " + uri;
            case CLASSIFICATION_CROSS_ORIGIN -> "URL host is cross-origin from the configured MCP endpoint: " + uri;
            default -> "URL is not valid: " + uri;
        };
    }

    /**
     * Aggregate result of {@link #classifyAll(URI, HostResolver, URI)}. Empty {@code codes}
     * means the destination is clean; any present code triggers gate behaviour.
     */
    public record Classification(List<String> codes, String resolvedAddress) {

        public Classification {
            codes = codes == null ? List.of() : List.copyOf(codes);
        }

        public static Classification of(String singleCode) {
            return new Classification(List.of(singleCode), null);
        }

        public boolean isClean() {
            return codes.isEmpty();
        }
    }

    private record ResolutionOutcome(List<InetAddress> addresses, boolean timedOut) {

        static ResolutionOutcome empty() {
            return new ResolutionOutcome(Collections.emptyList(), false);
        }

        static ResolutionOutcome timeout() {
            return new ResolutionOutcome(Collections.emptyList(), true);
        }

        static ResolutionOutcome of(List<InetAddress> addresses) {
            return new ResolutionOutcome(addresses, false);
        }
    }
}
