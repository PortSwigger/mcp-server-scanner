package com.mcpscanner.testutil;

import burp.api.montoya.persistence.Preferences;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public final class InMemoryPreferences implements Preferences {

    private final Map<String, String> strings = new HashMap<>();
    private final Map<String, Boolean> booleans = new HashMap<>();
    private final Map<String, Byte> bytes = new HashMap<>();
    private final Map<String, Short> shorts = new HashMap<>();
    private final Map<String, Integer> integers = new HashMap<>();
    private final Map<String, Long> longs = new HashMap<>();

    public Set<String> allKeys() {
        Set<String> keys = new java.util.HashSet<>();
        keys.addAll(strings.keySet());
        keys.addAll(booleans.keySet());
        keys.addAll(bytes.keySet());
        keys.addAll(shorts.keySet());
        keys.addAll(integers.keySet());
        keys.addAll(longs.keySet());
        return keys;
    }

    @Override public String getString(String key) { return strings.get(key); }
    @Override public void setString(String key, String value) { strings.put(key, value); }
    @Override public void deleteString(String key) { strings.remove(key); }
    @Override public Set<String> stringKeys() { return Set.copyOf(strings.keySet()); }
    @Override public Boolean getBoolean(String key) { return booleans.get(key); }
    @Override public void setBoolean(String key, boolean value) { booleans.put(key, value); }
    @Override public void deleteBoolean(String key) { booleans.remove(key); }
    @Override public Set<String> booleanKeys() { return Set.copyOf(booleans.keySet()); }
    @Override public Byte getByte(String key) { return bytes.get(key); }
    @Override public void setByte(String key, byte value) { bytes.put(key, value); }
    @Override public void deleteByte(String key) { bytes.remove(key); }
    @Override public Set<String> byteKeys() { return Set.copyOf(bytes.keySet()); }
    @Override public Short getShort(String key) { return shorts.get(key); }
    @Override public void setShort(String key, short value) { shorts.put(key, value); }
    @Override public void deleteShort(String key) { shorts.remove(key); }
    @Override public Set<String> shortKeys() { return Set.copyOf(shorts.keySet()); }
    @Override public Integer getInteger(String key) { return integers.get(key); }
    @Override public void setInteger(String key, int value) { integers.put(key, value); }
    @Override public void deleteInteger(String key) { integers.remove(key); }
    @Override public Set<String> integerKeys() { return Set.copyOf(integers.keySet()); }
    @Override public Long getLong(String key) { return longs.get(key); }
    @Override public void setLong(String key, long value) { longs.put(key, value); }
    @Override public void deleteLong(String key) { longs.remove(key); }
    @Override public Set<String> longKeys() { return Set.copyOf(longs.keySet()); }
}
