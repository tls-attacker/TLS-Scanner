package de.rub.nds.tlsscanner.clientscanner.util;

import java.util.Map;

public class MapUtil {
    private MapUtil() {
        throw new UnsupportedOperationException("Utility class");
    }

    @SuppressWarnings("squid:S2445") // sonarlint: Blocks should be synchronized on "private final" fields
    // we want to synchronize with "a", such that we don't merge "a" concurrently
    public static <K, V> void mergeIntoFirst(Map<K, V> a, Map<K, V> b) {
        synchronized (a) {
            for (Map.Entry<K, V> kv : b.entrySet()) {
                if (a.containsKey(kv.getKey())) {
                    // check if same
                    V objA = a.get(kv.getKey());
                    V objB = kv.getValue();
                    if (objA != null && objA != objB) {
                        throw new IllegalStateException("Cannot merge contradictory information");
                    }
                    // is same -> merge
                }
                a.put(kv.getKey(), kv.getValue());
            }
        }
    }

}
