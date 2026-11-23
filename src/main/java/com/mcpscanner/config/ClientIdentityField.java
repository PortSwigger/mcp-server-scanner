package com.mcpscanner.config;

import com.mcpscanner.ExtensionMetadata;

import java.net.URI;
import java.util.List;

public enum ClientIdentityField {
    NAME(Section.HANDSHAKE, "name", "Name", ExtensionMetadata.SCANNER_CLIENT_NAME, Rule.REQUIRED),
    TITLE(Section.HANDSHAKE, "title", "Title", "", Rule.OPTIONAL),
    VERSION(Section.HANDSHAKE, "version", "Version", ExtensionMetadata.VERSION, Rule.REQUIRED),
    DESCRIPTION(Section.HANDSHAKE, "description", "Description", "", Rule.OPTIONAL),
    WEBSITE_URL(Section.HANDSHAKE, "website_url", "Website URL", "", Rule.HTTP_URL),
    ICON_URL(Section.HANDSHAKE, "icon_url", "Icon URL", "", Rule.ICON_URL),
    OAUTH_CLIENT_NAME(Section.OAUTH, "oauth.client_name", "Client name", ExtensionMetadata.NAME, Rule.REQUIRED),
    CLIENT_URI(Section.OAUTH, "oauth.client_uri", "Homepage URL", "", Rule.HTTP_URL),
    LOGO_URI(Section.OAUTH, "oauth.logo_uri", "Logo URL", "", Rule.HTTP_URL),
    TOS_URI(Section.OAUTH, "oauth.tos_uri", "Terms of service URL", "", Rule.HTTP_URL),
    POLICY_URI(Section.OAUTH, "oauth.policy_uri", "Privacy policy URL", "", Rule.HTTP_URL),
    CONTACT(Section.OAUTH, "oauth.contact", "Contact email", "", Rule.OPTIONAL),
    SOFTWARE_ID(Section.OAUTH, "oauth.software_id", "Software ID", ExtensionMetadata.SOFTWARE_ID, Rule.OPTIONAL),
    SOFTWARE_VERSION(Section.OAUTH, "oauth.software_version", "Software version", "", Rule.OPTIONAL);

    public enum Section { HANDSHAKE, OAUTH }

    private enum Rule { OPTIONAL, REQUIRED, HTTP_URL, ICON_URL }

    private static final List<String> HTTP_SCHEMES = List.of("http", "https");

    private final Section section;
    private final String key;
    private final String label;
    private final String defaultValue;
    private final Rule rule;

    ClientIdentityField(Section section, String key, String label, String defaultValue, Rule rule) {
        this.section = section;
        this.key = SettingKey.CLIENT_IDENTITY.key(key);
        this.label = label;
        this.defaultValue = defaultValue;
        this.rule = rule;
    }

    public Section section() {
        return section;
    }

    public String key() {
        return key;
    }

    public String wireName() {
        return key.substring(key.lastIndexOf('.') + 1);
    }

    public String label() {
        return label;
    }

    public String defaultValue() {
        return defaultValue;
    }

    String normalize(String raw) {
        String value = raw == null ? "" : raw.trim();
        return value.isEmpty() ? defaultValue : value;
    }

    void validate(String value) {
        if (rule == Rule.REQUIRED && value.isEmpty()) {
            throw invalid("is required");
        }
        if (!value.isEmpty() && rule == Rule.HTTP_URL && !hasScheme(value, HTTP_SCHEMES)) {
            throw invalid("must be an http(s) URL");
        }
        if (!value.isEmpty() && rule == Rule.ICON_URL && !hasScheme(value, List.of("http", "https", "data"))) {
            throw invalid("must be an http(s) or data: URL");
        }
    }

    private IllegalArgumentException invalid(String reason) {
        return new IllegalArgumentException(label + " " + reason);
    }

    private static boolean hasScheme(String value, List<String> allowed) {
        try {
            String scheme = URI.create(value).getScheme();
            return scheme != null && allowed.contains(scheme.toLowerCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException malformed) {
            return false;
        }
    }
}
