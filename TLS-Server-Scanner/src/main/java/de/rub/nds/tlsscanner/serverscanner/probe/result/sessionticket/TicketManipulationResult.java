/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket;

import de.rub.nds.scanner.core.probe.result.SummarizableTestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsscanner.core.vector.VectorResponse;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketBitFlipVector;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

public class TicketManipulationResult implements SummarizableTestResult {
    public static final char CHR_ACCEPT = 'A';
    public static final char CHR_ACCEPT_DIFFERENT_SECRET = '#';
    public static final char CHR_REJECT = '_';
    public static final char CHR_UNKNOWN = '?';
    public static final char CHR_NO_RESULT = '.';
    public static final String CHR_CLASSIFICATIONS = "0123456789abcdefghijklmnopqrstuvwxyz";
    public static final String STR_NO_RESPONSES = "-";

    private final TestResults overallResult;
    private final Map<Integer, VectorResponse> responses;
    private final ResponseFingerprint acceptFingerprint;
    private final ResponseFingerprint acceptDifferentSecretFingerprint;
    private final ResponseFingerprint rejectFingerprint;

    public TicketManipulationResult(
            TestResults overallResult,
            Map<Integer, VectorResponse> responses,
            ResponseFingerprint acceptFingerprint,
            ResponseFingerprint acceptDifferentSecretFingerprint,
            ResponseFingerprint rejectFingerprint) {
        this.overallResult = overallResult;
        this.responses = responses;
        this.acceptFingerprint = acceptFingerprint;
        this.acceptDifferentSecretFingerprint = acceptDifferentSecretFingerprint;
        this.rejectFingerprint = rejectFingerprint;
    }

    public TicketManipulationResult(TestResults overallResult) {
        this(overallResult, null, null, null, null);
    }

    public String getResultsAsShortString() {
        return getResultsAsShortString(new HashMap<>(), false);
    }

    public String getResultsAsShortString(
            Map<ResponseFingerprint, Integer> classifications, boolean collapseBytes) {
        if (responses == null || responses.isEmpty()) {
            return STR_NO_RESPONSES;
        }

        int spaceEveryNBytes = 16;

        StringBuilder res = new StringBuilder(responses.size());
        Integer maxBit = responses.keySet().stream().max(Comparator.naturalOrder()).get();
        Integer maxByte = maxBit / 8;
        String byteSeparator = collapseBytes ? " " : "\n\t";
        for (int byteIndex = 0; byteIndex <= maxByte; byteIndex++) {
            if (byteIndex % spaceEveryNBytes == 0) {
                res.append(byteSeparator);
            }
            if (collapseBytes) {
                res.append(
                        getResultAsShortStringForRangeCollapsed(
                                byteIndex * 8, byteIndex * 8 + 8, classifications));
            } else {
                getResultAsShortStringForRange(
                        res, byteIndex * 8, byteIndex * 8 + 8, classifications);
                res.append(' ');
            }
        }
        return res.toString();
    }

    private ResponseFingerprint getFingerprintForPosition(int bitflipPosition) {
        VectorResponse response = responses.get(bitflipPosition);
        if (response != null) {
            TicketBitFlipVector vector = (TicketBitFlipVector) response.getVector();
            assert vector.position == bitflipPosition
                    : "Internal data corruption; ModifiedTicketFingerprint was stored wrongly in internal map";
            return response.getFingerprint();
        }
        return null;
    }

    private void getResultAsShortStringForRange(
            StringBuilder res,
            int firstBit,
            int exclusiveLastBit,
            Map<ResponseFingerprint, Integer> classifications) {
        for (int i = firstBit; i < exclusiveLastBit; i++) {
            ResponseFingerprint fingerprint = getFingerprintForPosition(i);

            if (fingerprint == null) {
                res.append(CHR_NO_RESULT);
            } else if (fingerprint.equals(acceptFingerprint)) {
                res.append(CHR_ACCEPT);
            } else if (fingerprint.equals(acceptDifferentSecretFingerprint)) {
                res.append(CHR_ACCEPT_DIFFERENT_SECRET);
            } else if (fingerprint.equals(rejectFingerprint)) {
                res.append(CHR_REJECT);
            } else {
                int classification = -1;
                if (classifications != null) {
                    classification =
                            classifications.computeIfAbsent(
                                    fingerprint, k -> classifications.size());
                }

                if (classification < 0 || classification > CHR_CLASSIFICATIONS.length()) {
                    res.append(CHR_UNKNOWN);
                } else {
                    res.append(CHR_CLASSIFICATIONS.charAt(classification));
                }
            }
        }
    }

    private char getResultAsShortStringForRangeCollapsed(
            int firstBit, int exclusiveLastBit, Map<ResponseFingerprint, Integer> classifications) {
        boolean accept = false;
        boolean acceptDifferentSecret = false;
        boolean reject = false;
        boolean custom = false;
        int customClassification = -1;
        boolean customMultiple = false;
        for (int i = firstBit; i < exclusiveLastBit; i++) {
            ResponseFingerprint fingerprint = getFingerprintForPosition(i);
            if (fingerprint == null) {
                continue;
            } else if (fingerprint.equals(acceptFingerprint)) {
                accept = true;
            } else if (fingerprint.equals(acceptDifferentSecretFingerprint)) {
                acceptDifferentSecret = true;
            } else if (fingerprint.equals(rejectFingerprint)) {
                reject = true;
            } else {
                int classification = -1;
                if (classifications != null) {
                    classification =
                            classifications.computeIfAbsent(
                                    fingerprint, k -> classifications.size());
                }
                if (!custom) {
                    custom = true;
                    customClassification = classification;
                } else if (customClassification != classification) {
                    customMultiple = true;
                }
            }
        }
        if (accept) {
            return CHR_ACCEPT;
        }
        if (acceptDifferentSecret) {
            return CHR_ACCEPT_DIFFERENT_SECRET;
        }
        if (customMultiple) {
            return CHR_UNKNOWN;
        }
        if (custom) {
            if (customClassification < 0 || customClassification > CHR_CLASSIFICATIONS.length()) {
                return CHR_UNKNOWN;
            } else {
                return CHR_CLASSIFICATIONS.charAt(customClassification);
            }
        }
        if (reject) {
            return CHR_REJECT;
        }
        return CHR_NO_RESULT;
    }

    public ResponseFingerprint getAcceptFingerprint() {
        return acceptFingerprint;
    }

    public ResponseFingerprint getAcceptDifferentSecretFingerprint() {
        return acceptDifferentSecretFingerprint;
    }

    public ResponseFingerprint getRejectFingerprint() {
        return rejectFingerprint;
    }

    public TestResults getOverallResult() {
        return this.overallResult;
    }

    public Map<Integer, VectorResponse> getResponses() {
        return this.responses;
    }

    @Override
    public TestResults getSummarizedResult() {
        return overallResult;
    }

    @Override
    public boolean isExplicitSummary() {
        return true;
    }
}
