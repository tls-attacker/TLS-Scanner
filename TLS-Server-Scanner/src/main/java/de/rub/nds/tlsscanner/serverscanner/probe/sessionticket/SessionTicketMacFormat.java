/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.sessionticket;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;

/**
 * Describes where to find the input text for the MAC computation. Does not make an assumption about whether the MAC is
 * in front or after the input.
 */
public class SessionTicketMacFormat {
    private static final int MIN_PREFIX_LEN = 0;
    private static final int MAX_PREFIX_LEN = 128;

    private static final int MIN_SUFFIX_LEN = 16;
    private static final int MAX_SUFFIX_LEN = 64;

    public static List<SessionTicketMacFormat> generateFormats(ScannerDetail scannerDetail, int ticketLength,
        int outputLength) {
        Set<Integer> prefixLengths = generatePrefixLengths(scannerDetail, ticketLength);
        Set<Integer> suffixLengths = prefixLengths;

        List<SessionTicketMacFormat> ret = new ArrayList<>(prefixLengths.size() * suffixLengths.size());
        for (int prefixLength : prefixLengths) {
            if (prefixLength < MIN_PREFIX_LEN || prefixLength > MAX_PREFIX_LEN) {
                continue;
            }
            for (int suffixLength : suffixLengths) {
                if (suffixLength < MIN_SUFFIX_LEN || suffixLength > MAX_SUFFIX_LEN) {
                    continue;
                }
                // we need at least 1B of input
                // and we need a prefix or suffix which contains the mac
                if (prefixLength + suffixLength < ticketLength
                    && (prefixLength >= outputLength || suffixLength >= outputLength)) {
                    ret.add(new SessionTicketMacFormat(prefixLength, suffixLength));
                }
            }
        }
        return ret;
    }

    private static Set<Integer> generatePrefixLengths(ScannerDetail scannerDetail, int ticketLength) {
        Set<Integer> ret = new HashSet<>();
        if (scannerDetail.getLevelValue() >= ScannerDetail.QUICK.getLevelValue()) {
            ret.add(0);
            ret.add(1);
            ret.add(8);
            ret.add(16);
        }
        if (scannerDetail.getLevelValue() >= ScannerDetail.NORMAL.getLevelValue()) {
            for (int i = 0; i < ticketLength; i += 16) {
                ret.add(i);
            }
        }
        if (scannerDetail.getLevelValue() >= ScannerDetail.DETAILED.getLevelValue()) {
            for (int i = 0; i < ticketLength; i += 8) {
                ret.add(i);
            }
        }
        if (scannerDetail.getLevelValue() >= ScannerDetail.ALL.getLevelValue()) {
            for (int i = 0; i < ticketLength; i++) {
                ret.add(i);
            }
        }
        return ret;
    }

    /**
     * Number of bytes in front of the input
     */
    private final int inputOffset;
    /**
     * Number of bytes after the input
     */
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
        return Arrays.copyOfRange(ticketBytes, ticketBytes.length - inputSuffixLength, ticketBytes.length);
    }

    public int getInputOffset() {
        return inputOffset;
    }

    public int getInputSuffixLength() {
        return inputSuffixLength;
    }
}
