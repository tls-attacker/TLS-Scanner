/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket;

import de.rub.nds.scanner.core.config.ScannerDetail;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Describes where to find the input text for the MAC computation. Does not make an assumption about
 * whether the MAC is in front or after the input.
 */
public class SessionTicketMacFormat {
    private static final int MIN_PREFIX_LEN = 0;
    private static final int MAX_PREFIX_LEN = 128;

    private static final int MIN_SUFFIX_LEN = 16;
    private static final int MAX_SUFFIX_LEN = 64;

    private static boolean validFormat(
            int prefixLength, int suffixLength, int outputLength, int ticketLength) {
        // we need at least 1B of input
        if (prefixLength + suffixLength >= ticketLength) {
            return false;
        }
        // and we need a prefix or suffix which contains the mac
        return prefixLength >= outputLength || suffixLength >= outputLength;
    }

    public static List<SessionTicketMacFormat> generateFormats(
            ScannerDetail scannerDetail, int ticketLength, int outputLength) {
        Set<Integer> prefixLengths = generatePrefixLengths(scannerDetail, ticketLength);
        Set<Integer> suffixLengths = prefixLengths;

        List<SessionTicketMacFormat> ret =
                new ArrayList<>(prefixLengths.size() * suffixLengths.size());
        for (int prefixLength : prefixLengths) {
            if (prefixLength < MIN_PREFIX_LEN || prefixLength > MAX_PREFIX_LEN) {
                continue;
            }
            for (int suffixLength : suffixLengths) {
                if (suffixLength < MIN_SUFFIX_LEN || suffixLength > MAX_SUFFIX_LEN) {
                    continue;
                }
                if (validFormat(prefixLength, suffixLength, outputLength, ticketLength)) {
                    ret.add(new SessionTicketMacFormat(prefixLength, suffixLength));
                }
            }
        }
        return ret;
    }

    private static Set<Integer> generatePrefixLengths(
            ScannerDetail scannerDetail, int ticketLength) {
        Set<Integer> ret = new HashSet<>();
        if (scannerDetail.getLevelValue() >= ScannerDetail.QUICK.getLevelValue()) {
            ret.add(0);
            ret.add(1);
            ret.add(8);
            ret.add(16);
        }
        if (scannerDetail.getLevelValue() >= ScannerDetail.NORMAL.getLevelValue()) {
            int stepSize = 16;
            if (scannerDetail.getLevelValue() >= ScannerDetail.DETAILED.getLevelValue()) {
                stepSize = 8;
            }
            if (scannerDetail.getLevelValue() >= ScannerDetail.ALL.getLevelValue()) {
                stepSize = 1;
            }

            for (int i = 0; i < ticketLength; i += stepSize) {
                ret.add(i);
            }
        }
        return ret;
    }

    /** Number of bytes in front of the input */
    private final int inputOffset;
    /** Number of bytes after the input */
    private final int inputSuffixLength;

    public SessionTicketMacFormat(int inputOffset, int inputSuffixLength) {
        this.inputOffset = inputOffset;
        this.inputSuffixLength = inputSuffixLength;
    }

    public byte[] getMacInput(byte[] ticketBytes) {
        return Arrays.copyOfRange(ticketBytes, inputOffset, ticketBytes.length - inputSuffixLength);
    }

    public byte[] getInputPrefix(byte[] ticketBytes) {
        return Arrays.copyOfRange(ticketBytes, 0, inputOffset);
    }

    public byte[] getInputSuffix(byte[] ticketBytes) {
        return Arrays.copyOfRange(
                ticketBytes, ticketBytes.length - inputSuffixLength, ticketBytes.length);
    }

    public int getInputOffset() {
        return inputOffset;
    }

    public int getInputSuffixLength() {
        return inputSuffixLength;
    }
}
