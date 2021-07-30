/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.util.helper;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;

public class DuoMapQ<K1, K2, V> {
    private final Map<K1, SingleMapQ<K2, V>> map = new HashMap<>();

    public synchronized Triple<K1, K2, V> dequeueAny() {
        for (K1 k : map.keySet()) {
            Pair<K2, V> ret = dequeueAnyWith(k);
            if (ret != null) {
                return Triple.of(k, ret.getLeft(), ret.getRight());
            }
        }
        return null;
    }

    public synchronized Pair<K2, V> dequeueAnyWith(K1 k1) {
        SingleMapQ<K2, V> internalMap;
        internalMap = map.get(k1);
        if (internalMap == null) {
            return null;
        }
        Pair<K2, V> ret = internalMap.dequeueAny();
        if (internalMap.isEmpty()) {
            map.remove(k1);
        }
        return ret;
    }

    public synchronized V dequeue(K1 k1, K2 k2) {
        SingleMapQ<K2, V> internalMap;
        internalMap = map.get(k1);
        if (internalMap == null) {
            return null;
        }
        V ret = internalMap.dequeue(k2);
        if (internalMap.isEmpty()) {
            map.remove(k1);
        }
        return ret;
    }

    public synchronized void enqueue(K1 k1, K2 k2, V v) {
        SingleMapQ<K2, V> internalMap;
        internalMap = map.computeIfAbsent(k1, _k -> new SingleMapQ<>());
        internalMap.enqueue(k2, v);
    }
}
