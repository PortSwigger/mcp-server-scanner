package com.mcpscanner.testutil;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.config.ExtensionConfigStore;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

public final class InMemoryPersistedObject {

    private InMemoryPersistedObject() {}

    public static ExtensionConfigStore configStore() {
        return new ExtensionConfigStore(create(), new InMemoryPreferences(), mock(Logging.class));
    }

    public static PersistedObject create() {
        Map<String, Object> values = new HashMap<>();
        PersistedObject store = mock(PersistedObject.class);
        lenient().when(store.getBoolean(anyString())).thenAnswer(inv -> (Boolean) values.get(inv.getArgument(0)));
        lenient().when(store.getString(anyString())).thenAnswer(inv -> (String) values.get(inv.getArgument(0)));
        lenient().when(store.getLong(anyString())).thenAnswer(inv -> (Long) values.get(inv.getArgument(0)));
        lenient().doAnswer(inv -> values.put(inv.getArgument(0), inv.getArgument(1)))
                .when(store).setLong(anyString(), anyLong());
        lenient().doAnswer(inv -> values.remove(inv.getArgument(0))).when(store).deleteLong(anyString());
        lenient().doAnswer(inv -> values.put(inv.getArgument(0), inv.getArgument(1)))
                .when(store).setBoolean(anyString(), anyBoolean());
        lenient().doAnswer(inv -> values.put(inv.getArgument(0), inv.getArgument(1)))
                .when(store).setString(anyString(), anyString());
        lenient().when(store.getInteger(anyString())).thenAnswer(inv -> (Integer) values.get(inv.getArgument(0)));
        lenient().doAnswer(inv -> values.put(inv.getArgument(0), inv.getArgument(1)))
                .when(store).setInteger(anyString(), anyInt());
        lenient().doAnswer(inv -> values.remove(inv.getArgument(0))).when(store).deleteInteger(anyString());
        lenient().when(store.booleanKeys()).thenAnswer(inv -> keysOf(values, Boolean.class));
        lenient().when(store.stringKeys()).thenAnswer(inv -> keysOf(values, String.class));
        lenient().when(store.integerKeys()).thenAnswer(inv -> keysOf(values, Integer.class));
        lenient().when(store.longKeys()).thenAnswer(inv -> keysOf(values, Long.class));
        lenient().doAnswer(inv -> values.remove(inv.getArgument(0))).when(store).deleteBoolean(anyString());
        lenient().doAnswer(inv -> values.remove(inv.getArgument(0))).when(store).deleteString(anyString());
        return store;
    }

    private static Set<String> keysOf(Map<String, Object> values, Class<?> type) {
        return values.entrySet().stream().filter(entry -> type.isInstance(entry.getValue()))
                .map(Map.Entry::getKey).collect(Collectors.toSet());
    }
}
