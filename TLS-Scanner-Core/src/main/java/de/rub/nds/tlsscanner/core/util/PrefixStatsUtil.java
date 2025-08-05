/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.util;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

public class PrefixStatsUtil {
    private PrefixStatsUtil() {}

    /**
     * Compute after which prefix length how many divergences happen. I.e. build a prefix tree and
     * count divergences at each level.
     *
     * <p>The strings "AAB", "AAC", "AAD" would find 3 divergences after depth 2; this means that
     * the prefix will most likely have the length 2
     *
     * @param strings (Byte)strings to analyze for common prefixes
     * @return A map mapping {prefix length} to {divergences after this length}
     */
    public static Map<Integer, Integer> computePrefixDivergences(List<byte[]> strings) {
        Map<Integer, Integer> result = new HashMap<>();
        byte[] prefixThusFar = new byte[0];

        computePrefixDivergences(strings, result, prefixThusFar);
        return result;
    }

    private static void computePrefixDivergences(
            List<byte[]> strings, Map<Integer, Integer> result, byte[] prefixThusFar) {
        // compute after which prefix length how many divergences happen
        // we basically build a preix tree
        // we stop generating child nodes if we already have only a single ticket at this depth
        // however, we don't really build a tree, but only remember the (sumed up) degree in each
        // depth

        if (strings.size() < 2) {
            return;
        }
        int pos = prefixThusFar.length;
        Map<Byte, List<byte[]>> nextPrefixes = new HashMap<>();
        // get prefixes with 1B more length
        for (byte[] str : strings) {
            if (pos < str.length) {
                byte next = str[pos];
                nextPrefixes.computeIfAbsent(next, k -> new LinkedList<byte[]>());
                nextPrefixes.get(next).add(str);
            }
            // we ignore early ending strings (for now)
            // TODO count early ending as divergence if other strings do not end there
        }
        // add number of divergences at this depth to result
        result.compute(
                prefixThusFar.length, (k, v) -> (v == null ? 0 : v) + nextPrefixes.keySet().size());
        // DFS for divergences
        for (Entry<Byte, List<byte[]>> item : nextPrefixes.entrySet()) {
            byte[] nextPrefix = Arrays.copyOf(prefixThusFar, prefixThusFar.length + 1);
            nextPrefix[prefixThusFar.length] = item.getKey();
            computePrefixDivergences(item.getValue(), result, nextPrefix);
        }
    }
}
