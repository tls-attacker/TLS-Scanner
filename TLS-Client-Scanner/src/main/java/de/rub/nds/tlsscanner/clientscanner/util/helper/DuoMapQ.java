/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.util.helper;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;

public class DuoMapQ<K1, K2, V> {
    private Map<K1, SingleMapQ<K2, V>> map = new HashMap<>();

    public Triple<K1, K2, V> dequeueAny() {
        for (K1 k : map.keySet()) {
            Pair<K2, V> ret = dequeueAnyWith(k);
            if (ret != null) {
                Triple.of(k, ret.getLeft(), ret.getRight());
            }
        }
        return null;
    }

    public Pair<K2, V> dequeueAnyWith(K1 k1) {
        SingleMapQ<K2, V> internalMap;
        internalMap = map.get(k1);
        if (internalMap == null) {
            return null;
        }
        Pair<K2, V> ret = internalMap.dequeueAny();
        synchronized (map) {
            if (internalMap.isEmpty()) {
                map.remove(k1);
            }
        }
        return ret;
    }

    public V dequeue(K1 k1, K2 k2) {
        SingleMapQ<K2, V> internalMap;
        internalMap = map.get(k1);
        if (internalMap == null) {
            return null;
        }
        V ret = internalMap.dequeue(k2);
        synchronized (map) {
            if (internalMap.isEmpty()) {
                map.remove(k1);
            }
        }
        return ret;
    }

    public void enqueue(K1 k1, K2 k2, V v) {
        SingleMapQ<K2, V> internalMap;
        synchronized (map) {
            internalMap = map.get(k1);
            if (internalMap == null) {
                internalMap = new SingleMapQ<>();
                map.put(k1, internalMap);
            }
            // adding the element is still synced, as we do not want internalMap
            // to possibly be removed from map
            synchronized (internalMap) {
                internalMap.enqueue(k2, v);
            }
        }
    }
}
