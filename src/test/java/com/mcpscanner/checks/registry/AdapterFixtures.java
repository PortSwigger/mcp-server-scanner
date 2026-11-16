package com.mcpscanner.checks.registry;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

final class AdapterFixtures {

    private AdapterFixtures() {
    }

    static ScanCheckSettings settingsAllowing(boolean enabled) {
        ScanCheckSettings settings = mock(ScanCheckSettings.class);
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(enabled);
        return settings;
    }

    static ScanCheckType registeredScanCheckType(ManagedCheck check) {
        ActiveCheckRegistrar registrar = mock(ActiveCheckRegistrar.class);
        check.registerWith(registrar);
        ArgumentCaptor<ScanCheckType> type = ArgumentCaptor.forClass(ScanCheckType.class);
        verify(registrar).register(org.mockito.ArgumentMatchers.same((ActiveScanCheck) check), type.capture());
        return type.getValue();
    }

    static HttpRequestResponse baseOn(String host) {
        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn(host);
        when(service.port()).thenReturn(443);
        when(service.secure()).thenReturn(true);
        HttpRequestResponse base = mock(HttpRequestResponse.class);
        when(base.httpService()).thenReturn(service);
        return base;
    }

    static HttpRequestResponse streamedBaseFor(HttpRequest request) {
        HttpRequestResponse base = baseOn("mcp.example.test");
        when(base.request()).thenReturn(request);
        when(base.response()).thenReturn(null);
        when(base.hasResponse()).thenReturn(false);
        return base;
    }
}
