/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.MacAlgorithm;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.util.ComparableByteArray;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.util.Arrays;

public class DefaultKeys {

    private DefaultKeys() {}

    private static Map<Pair<Integer, ScannerDetail>, Collection<byte[]>> keySetsCache =
            new ConcurrentHashMap<>();
    private static Map<Pair<MacAlgorithm, ScannerDetail>, Collection<Integer>> keyLengthsCache =
            new ConcurrentHashMap<>();

    private static ComparableByteArray fixedKey(int length, String values) {
        return fixedKey(length, ArrayConverter.hexStringToByteArray(values));
    }

    private static ComparableByteArray fixedKey(int length, byte[] value) {
        if (value.length == length) {
            return new ComparableByteArray(value);
        } else {
            return null;
        }
    }

    private static ComparableByteArray computeConstantKey(int length, byte value) {
        byte[] key = new byte[length];
        Arrays.fill(key, value);
        return new ComparableByteArray(key);
    }

    private static ComparableByteArray computeRepetitiveKey(int length, String values) {
        return computeRepetitiveKey(length, ArrayConverter.hexStringToByteArray(values));
    }

    private static ComparableByteArray computeRepetitiveKey(int length, byte[] values) {
        byte[] key = new byte[length];
        for (int i = 0; i < length; i++) {
            key[i] = values[i % values.length];
        }
        return new ComparableByteArray(key);
    }

    private static ComparableByteArray computeCountingKey(int length, byte start) {
        return computeCountingKey(length, start, 1);
    }

    private static ComparableByteArray computeCountingKey(int length, byte start, int step) {
        byte[] key = new byte[length];
        byte value = start;
        for (int i = 0; i < length; i++) {
            key[i] = value;
            value += step;
        }
        return new ComparableByteArray(key);
    }

    public static Collection<byte[]> getKeys(int length, ScannerDetail scannerDetail) {
        return Collections.unmodifiableCollection(
                keySetsCache.computeIfAbsent(
                        Pair.of(length, scannerDetail), DefaultKeys::getKeysInternal));
    }

    private static Collection<byte[]> getKeysInternal(Pair<Integer, ScannerDetail> pair) {
        int length = pair.getLeft();
        ScannerDetail scannerDetail = pair.getRight();
        Set<ComparableByteArray> keys = new HashSet<>();

        if (scannerDetail.getLevelValue() >= ScannerDetail.QUICK.getLevelValue()) {

            // discovered during scan
            keys.add(fixedKey(length, "31313131313131310000000000000000"));
            keys.add(
                    fixedKey(
                            length,
                            "3131313131313131313131313131313100000000000000000000000000000000"));

            keys.add(computeConstantKey(length, (byte) 0x00));
            keys.add(computeCountingKey(length, (byte) 0x00));
        }
        if (scannerDetail.getLevelValue() >= ScannerDetail.NORMAL.getLevelValue()) {
            // keys deemed simple
            keys.add(computeConstantKey(length, (byte) 0xff));
            keys.add(computeCountingKey(length, (byte) 0x01));
            keys.add(computeCountingKey(length, (byte) 0x00, 0x11));
            keys.add(computeCountingKey(length, (byte) 0x01, 0x11));
            // common offsets of counting keys (e.g. counting key for mac+enc)
            keys.add(computeCountingKey(length, (byte) 0x10));
            keys.add(computeCountingKey(length, (byte) 0x11));
            keys.add(computeCountingKey(length, (byte) 0x20));
            keys.add(computeCountingKey(length, (byte) 0x21));
            // https://stackoverflow.com/a/127404/3578387
            // https://en.wikipedia.org/wiki/Magic_number_(programming)#Debug_values
            keys.add(computeConstantKey(length, (byte) 0xA5));
            keys.add(computeConstantKey(length, (byte) 0xAB));
            keys.add(computeConstantKey(length, (byte) 0xA5));
            keys.add(computeConstantKey(length, (byte) 0xAB));
            keys.add(computeConstantKey(length, (byte) 0xCC));
            keys.add(computeConstantKey(length, (byte) 0xCD));
            keys.add(computeConstantKey(length, (byte) 0xDD));
            keys.add(computeConstantKey(length, (byte) 0xFD));

            keys.add(computeRepetitiveKey(length, "ABBABABE"));
            keys.add(computeRepetitiveKey(length, "BAADF00D"));
            keys.add(computeRepetitiveKey(length, "BADBADBADBAD"));
            keys.add(computeRepetitiveKey(length, "BADDCAFE"));
            keys.add(computeRepetitiveKey(length, "CAFEFEED"));
            keys.add(computeRepetitiveKey(length, "DEADBEEF"));
            keys.add(computeRepetitiveKey(length, "DEADF00D"));
            keys.add(computeRepetitiveKey(length, "FEEEFEEE"));

            // adding these for now
            // complete list from
            // https://en.wikipedia.org/wiki/Magic_number_(programming)#Debug_values
            keys.add(computeRepetitiveKey(length, "00008123"));
            keys.add(computeRepetitiveKey(length, "1BADB002"));
            keys.add(computeRepetitiveKey(length, "8BADF00D"));
            keys.add(computeRepetitiveKey(length, "A5"));
            keys.add(computeRepetitiveKey(length, "ABABABAB"));
            keys.add(computeRepetitiveKey(length, "ABADBABE"));
            keys.add(computeRepetitiveKey(length, "ABBABABE"));
            keys.add(computeRepetitiveKey(length, "ABADCAFE"));
            keys.add(computeRepetitiveKey(length, "B16B00B5"));
            keys.add(computeRepetitiveKey(length, "BAADF00D"));
            keys.add(computeRepetitiveKey(length, "BAAAAAAD"));
            keys.add(computeRepetitiveKey(length, "BAD22222"));
            keys.add(computeRepetitiveKey(length, "BADBADBADBAD"));
            keys.add(computeRepetitiveKey(length, "BADC0FFEE0DDF00D"));
            keys.add(computeRepetitiveKey(length, "BADDCAFE"));
            keys.add(computeRepetitiveKey(length, "BBADBEEF"));
            keys.add(computeRepetitiveKey(length, "BEEFCACE"));
            keys.add(computeRepetitiveKey(length, "C00010FF"));
            keys.add(computeRepetitiveKey(length, "CAFEBABE"));
            keys.add(computeRepetitiveKey(length, "CAFED00D"));
            keys.add(computeRepetitiveKey(length, "CAFEFEED"));
            keys.add(computeRepetitiveKey(length, "CCCCCCCC"));
            keys.add(computeRepetitiveKey(length, "CDCDCDCD"));
            keys.add(computeRepetitiveKey(length, "0D15EA5E"));
            keys.add(computeRepetitiveKey(length, "DDDDDDDD"));
            keys.add(computeRepetitiveKey(length, "DEAD10CC"));
            keys.add(computeRepetitiveKey(length, "DEADBABE"));
            keys.add(computeRepetitiveKey(length, "DEADBEEF"));
            keys.add(computeRepetitiveKey(length, "DEADCAFE"));
            keys.add(computeRepetitiveKey(length, "DEADC0DE"));
            keys.add(computeRepetitiveKey(length, "DEADFA11"));
            keys.add(computeRepetitiveKey(length, "DEADF00D"));
            keys.add(computeRepetitiveKey(length, "DEFEC8ED"));
            keys.add(computeRepetitiveKey(length, "DEADDEAD"));
            keys.add(computeRepetitiveKey(length, "D00D2BAD"));
            keys.add(computeRepetitiveKey(length, "EBEBEBEB"));
            keys.add(computeRepetitiveKey(length, "FADEDEAD"));
            keys.add(computeRepetitiveKey(length, "FDFDFDFD"));
            keys.add(computeRepetitiveKey(length, "FEE1DEAD"));
            keys.add(computeRepetitiveKey(length, "FEEDFACE"));
            keys.add(computeRepetitiveKey(length, "FEEEFEEE"));

            keys.add(fixedKey(length, "00112233445566778899aabbccddeeff"));

            // https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
            // A.1/page 27
            keys.add(fixedKey(length, "2b7e151628aed2a6abf7158809cf4f3c"));
            // A.2/page 28
            keys.add(fixedKey(length, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"));
            // A.3/page 30
            keys.add(
                    fixedKey(
                            length,
                            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"));
            // B/page 34
            keys.add(fixedKey(length, "3243f6a8885a308d313198a2e0370734")); // input
            // key already handled by A.1
            // C is covered by counting keys

            // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
            // F.1
            // only contains keys already listed above

        }
        if (scannerDetail.getLevelValue() >= ScannerDetail.DETAILED.getLevelValue()) {
            for (int val = Byte.MIN_VALUE; val <= Byte.MAX_VALUE; val += 16) {
                keys.add(computeConstantKey(length, (byte) val));
                keys.add(computeCountingKey(length, (byte) val));
            }

            for (int val = Byte.MIN_VALUE + 1; val <= Byte.MAX_VALUE; val += 16) {
                keys.add(computeConstantKey(length, (byte) val));
                keys.add(computeCountingKey(length, (byte) val));
            }
            for (int val = Byte.MIN_VALUE + 15; val <= Byte.MAX_VALUE; val += 16) {
                keys.add(computeConstantKey(length, (byte) val));
                keys.add(computeCountingKey(length, (byte) val));
            }
        }
        if (scannerDetail.getLevelValue() >= ScannerDetail.ALL.getLevelValue()) {
            for (int val = Byte.MIN_VALUE; val <= Byte.MAX_VALUE; val++) {
                keys.add(computeConstantKey(length, (byte) val));
                keys.add(computeCountingKey(length, (byte) val));
            }
        }

        return keys.stream()
                .filter(x -> x != null)
                .map(ComparableByteArray::getArray)
                .collect(Collectors.toList());
    }

    /**
     * Get key sizes we want to check.
     *
     * @param algo Mac Algorithm that is assumed
     * @param scannerDetail Detail the scanner is running in. Affects how many key sizes are
     *     proposed
     * @return A Set of key sizes that should be considered.
     */
    public static Collection<Integer> getKeySizes(MacAlgorithm algo, ScannerDetail scannerDetail) {
        return Collections.unmodifiableCollection(
                keyLengthsCache.computeIfAbsent(
                        Pair.of(algo, scannerDetail), DefaultKeys::getKeySizesInternal));
    }

    private static Collection<Integer> getKeySizesInternal(Pair<MacAlgorithm, ScannerDetail> pair) {
        MacAlgorithm algo = pair.getLeft();
        ScannerDetail scannerDetail = pair.getRight();
        Set<Integer> ret = new HashSet<>();
        if (scannerDetail.getLevelValue() >= ScannerDetail.QUICK.getLevelValue()) {
            // add key and output size (if they even differ)
            ret.add(algo.getKeySize());
            ret.add(algo.getMacLength());
        }
        ret.add(16);
        ret.add(32);
        ret.remove(
                0); // 0 length keys just throw java exceptions; in hmac this corresponds to a key
        // of the form
        // 00...00, so this case is covered
        return ret;
    }
}
