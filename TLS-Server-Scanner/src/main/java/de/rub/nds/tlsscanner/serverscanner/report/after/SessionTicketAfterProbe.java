/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.after;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.util.StaticTicketCrypto;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.DefaultKeys;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.PossibleSecret;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketEncryptionFormat;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketMacFormat;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.TicketEncryptionAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.TicketTls12;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket.FoundDefaultHmacKey;
import de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket.FoundDefaultStek;
import de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket.SessionTicketAfterProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket.TicketResult;
import de.rub.nds.tlsscanner.serverscanner.util.ArrayUtil;
import de.rub.nds.tlsscanner.serverscanner.util.PrefixStatsUtil;

public class SessionTicketAfterProbe extends AfterProbe {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final MacAlgorithm[] HMAC_ALGORITHMS = { MacAlgorithm.HMAC_MD5, MacAlgorithm.HMAC_SHA1,
        MacAlgorithm.HMAC_SHA256, MacAlgorithm.HMAC_SHA384, MacAlgorithm.HMAC_SHA512, };
    private static final TicketEncryptionAlgorithm[] ENCRYPTION_ALGORITHMS = TicketEncryptionAlgorithm.values();
    private static final int MIN_ASCII_LENGTH = 8;

    private ScannerConfig scannerConfig;

    public SessionTicketAfterProbe(ScannerConfig scannerConfig) {
        this.scannerConfig = scannerConfig;
    }

    @Override
    public void analyze(SiteReport report) {
        for (Entry<ProtocolVersion, TicketResult> entry : report.getSessionTicketProbeResult().getResultMap()
            .entrySet()) {
            analyze(entry.getKey(), entry.getValue().getTicketList(), scannerConfig.getScanDetail())
                .writeToSiteReport(report);
        }
    }

    public static SessionTicketAfterProbeResult analyze(ProtocolVersion version, List<Ticket> tickets,
        ScannerDetail detail) {
        SessionTicketAfterProbeResult result = new SessionTicketAfterProbeResult(version);

        result.setTicketLengthOccurences(analyzeTicketLength(tickets));
        result.setKeyNameLength(analyzeKeyNameLength(tickets));
        // TODO: Analyze IV repetition/common bytes

        result.setAsciiStringsFound(analyzeAscii(tickets));

        result.setContainsPlainSecret(analyzeUnencryptedTicket(tickets));
        result.setFoundDefaultStek(analyzeDefaultStek(tickets, result.getKeyNameLength(), detail));
        result.setFoundDefaultHmacKey(analyzeDefaultHmacKey(tickets, detail));

        result.setDiscoveredReusedKeystream(analyzeReusedKeyStream(tickets));

        return result;
    }

    /**
     * Get the lengths of the ticket. Returns a Map of lengths and occurences.
     *
     * @param  tickets
     *                 Tickets to analyze
     * @return         Returns a Map of lengths and how often it occurred. The keys are the lengths. The values the
     *                 occurences.
     */
    private static Map<Integer, Integer> analyzeTicketLength(List<Ticket> tickets) {
        Map<Integer, Integer> ticketLengthOccurences = new HashMap<>();
        for (Ticket ticket : tickets) {
            int len = ticket.getTicketBytesOriginal().length;
            ticketLengthOccurences.compute(len, (k, v) -> (v == null) ? 1 : v + 1);
        }
        return ticketLengthOccurences;
    }

    /**
     * Get the (probable) length of any prefix (which we consider to be the key name).
     *
     * @param  tickets
     *                 Tickets to analyze
     * @return         The most likely length of the key name
     */
    private static int analyzeKeyNameLength(List<Ticket> tickets) {
        Map<Integer, Integer> lengthToDivergences = PrefixStatsUtil.computePrefixDivergences(
            tickets.stream().map(Ticket::getTicketBytesOriginal).collect(Collectors.toList()));
        // find prefix length with most divergences afterwards
        // this means we want the key with the highest value
        // This approach should solve two problems:
        // - the tickets randomly starting with the same byte (after the key name)
        // - hitting a load balancer/different servers
        Entry<Integer, Integer> lengthAndNumDivergences = null;
        for (Entry<Integer, Integer> item : lengthToDivergences.entrySet()) {
            LOGGER.debug("Depth, Divergences: {}, {}", item.getKey(), item.getValue());
            if (lengthAndNumDivergences == null || lengthAndNumDivergences.getValue() < item.getValue()) {
                lengthAndNumDivergences = item;
            }
        }
        return lengthAndNumDivergences == null ? 0 : lengthAndNumDivergences.getKey();
    }

    /**
     * Get ascii strings from the tickets. This finds substrings of consecutive ascii characters. It stores all strings
     * over MIN_ASCII_LENGTH (8 Bytes) and the longest string (useful if < 8B).
     *
     * @param  tickets
     *                 Tickets to analyze
     * @return         List of ASCII-Strings found in the ticket.
     */
    private static List<String> analyzeAscii(List<Ticket> tickets) {
        String longestAsciiFound = "";
        List<String> strings = new ArrayList<>();
        for (Ticket ticket : tickets) {
            byte[] ticketBytes = ticket.getTicketBytesOriginal();

            // append a 0 byte: This way the last byte will not be within ascii -> the else branch will be triggered
            // -> we do not need to repeat handling the end of the string after the for loop
            ticketBytes = Arrays.copyOf(ticketBytes, ticketBytes.length + 1);
            assert ticketBytes[ticketBytes.length - 1] == 0;

            int currentAsciiStart = 0;
            for (int i = 0; i < ticketBytes.length; i++) {
                byte b = ticketBytes[i];
                if (b >= 0x20 && b <= 0x7F) {
                    // is ascii
                } else {
                    if (currentAsciiStart < i) {
                        // handle string end
                        int length = i - currentAsciiStart;
                        String newFind = new String(ticketBytes, currentAsciiStart, length);
                        if (length >= MIN_ASCII_LENGTH) {
                            strings.add(newFind);
                        }
                        if (length > longestAsciiFound.length()) {
                            longestAsciiFound = newFind;
                        }
                    }
                    currentAsciiStart = i + 1;
                }
            }
        }

        if (longestAsciiFound.length() < MIN_ASCII_LENGTH) {
            // if the longest string is still too short, just add it
            strings.add(longestAsciiFound);
        }
        return strings;
    }

    private static PossibleSecret analyzeUnencryptedTicket(List<Ticket> tickets) {
        for (Ticket ticket : tickets) {
            PossibleSecret foundSecret = ticket.checkContainsSecrets(ticket.getTicketBytesOriginal());
            if (foundSecret != null) {
                return foundSecret;
            }
        }
        return null;
    }

    private static FoundDefaultStek analyzeDefaultStek(List<Ticket> tickets, int keyNameLength, ScannerDetail detail) {
        // for ticket
        // for algorithm
        // for format
        // for key
        // try decrypt and find secret

        // TODO optimize to reduce "duplicate" decryptions
        // e.g. ECB and CBC modes only care about offsets of 0-15. 16 Is again equivalent to 0 (with first block
        // missing)
        for (Ticket ticket : tickets) {
            byte[] ticketBytes = ticket.getTicketBytesOriginal();
            for (TicketEncryptionAlgorithm algo : ENCRYPTION_ALGORITHMS) {
                for (SessionTicketEncryptionFormat format : SessionTicketEncryptionFormat.generateFormats(detail,
                    ticketBytes.length, algo.ivNonceSize, keyNameLength)) {

                    byte[] iv = format.getIvNonce(ticketBytes);
                    byte[] ciphertext = format.getCiphertextTruncated(ticketBytes, algo.blockSize);

                    for (byte[] key : DefaultKeys.getKeys(algo.keySize, detail)) {
                        byte[] decState = algo.decryptIgnoringIntegrity(key, iv, ciphertext);
                        PossibleSecret foundSecret = ticket.checkContainsSecrets(decState);
                        if (foundSecret != null) {
                            return new FoundDefaultStek(algo, format, key, foundSecret);
                        }
                    }
                }
            }
        }
        return null;
    }

    private static FoundDefaultHmacKey analyzeDefaultHmacKey(List<Ticket> tickets, ScannerDetail detail) {
        // for ticket
        // for algorithm
        // for format
        // for keysize
        // for key
        // check whether MAC is included (in non input range)
        for (Ticket ticket : tickets) {
            byte[] ticketBytes = ticket.getTicketBytesOriginal();

            for (MacAlgorithm algo : HMAC_ALGORITHMS) {
                for (SessionTicketMacFormat format : SessionTicketMacFormat.generateFormats(detail, ticketBytes.length,
                    algo.getSize())) {
                    byte[] plaintext = format.getMacInput(ticketBytes);
                    byte[] prefix = format.getInputPrefix(ticketBytes);
                    byte[] suffix = format.getInputSuffix(ticketBytes);

                    for (int keySize : DefaultKeys.getKeySizes(algo, detail)) {
                        for (byte[] key : DefaultKeys.getKeys(keySize, detail)) {

                            try {
                                byte[] tag = StaticTicketCrypto.generateHMAC(algo, plaintext, key);
                                if (ArrayUtil.findSubarray(prefix, tag) != -1
                                    || ArrayUtil.findSubarray(suffix, tag) != -1) {

                                    return new FoundDefaultHmacKey(algo, format, key);
                                }
                            } catch (CryptoException e) {
                                LOGGER.error("Internal error while checking default MAC", e);
                            }

                        }
                    }
                }
            }
        }
        return null;
    }

    private static byte[] xor(byte[] a, byte[] b) {
        if (a.length > b.length) {
            return xor(b, a); // NOSONAR S2234
        }
        assert a.length <= b.length;

        byte[] ret = new byte[a.length];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = (byte) (a[i] ^ b[i]);
        }
        return ret;
    }

    private static boolean byteArraysEqual(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
    }

    private static List<PossibleSecret> xorSecrets(Ticket ticketA, Ticket ticketB, boolean skipSameSecrets) {
        List<PossibleSecret> xoredSecrets = new LinkedList<>();
        for (PossibleSecret secretA : ticketA.getPossibleSecrets()) {
            for (PossibleSecret secretB : ticketB.getPossibleSecrets()) {
                if (secretA.secretType == secretB.secretType && secretA.value.length == secretB.value.length) {
                    if (skipSameSecrets && byteArraysEqual(secretA.value, secretB.value)) {
                        continue;
                    }
                    xoredSecrets.add(new PossibleSecret(secretA.secretType, xor(secretA.value, secretB.value)));
                }
            }
        }
        return xoredSecrets;
    }

    /**
     * Checks whether two tickets were encrypted using the same keystream (assuming XOR). For example, this can happen
     * if the IV/Nonce in CTR/GCM are reused.
     *
     * @param tickets
     *                Tickets to analyze
     */
    private static PossibleSecret analyzeReusedKeyStream(List<Ticket> tickets) {
        for (int i = 0; i < tickets.size(); i++) {
            Ticket ticketA = tickets.get(i);
            for (int j = i + 1; j < tickets.size(); j++) {
                Ticket ticketB = tickets.get(j);
                byte[] xoredTickets = xor(ticketA.getTicketBytesOriginal(), ticketB.getTicketBytesOriginal());
                Ticket combinedSecrets = new TicketTls12(null, null, xorSecrets(ticketA, ticketB, true));

                PossibleSecret foundSecret = combinedSecrets.checkContainsSecrets(xoredTickets);
                if (foundSecret != null) {
                    return foundSecret;
                }
            }
        }
        return null;
    }

    private static double log2(long N) {
        return (Math.log(N) / Math.log(2));
    }

    private static void checkNumberOfEncryptions(int ticketBytesLength) {
        int keyNameLength = 16;
        System.out.println("Encryptions");
        for (ScannerDetail detail : ScannerDetail.values()) {
            long numAlgorithms = 0;
            long numFormatsMax = 0;
            long numKeysMax = 0;

            long total = 0;
            numAlgorithms = ENCRYPTION_ALGORITHMS.length;
            for (TicketEncryptionAlgorithm algo : ENCRYPTION_ALGORITHMS) {
                long numFormats = SessionTicketEncryptionFormat
                    .generateFormats(detail, ticketBytesLength, algo.ivNonceSize, keyNameLength).size();
                long numKeys = DefaultKeys.getKeys(algo.keySize, detail).size();
                numFormatsMax = Math.max(numFormatsMax, numFormats);
                numKeysMax = Math.max(numKeysMax, numKeys);
                total += numFormats * numKeys;
            }
            System.out.println(String.format("%-9s %2d %4d %3d %10d %4.1f", detail, numAlgorithms, numFormatsMax,
                numKeysMax, total, log2(total)));
        }
        System.out.println();
    }

    private static void checkNumberOfMacs(int ticketBytesLength) {
        System.out.println("MACs");
        for (ScannerDetail detail : ScannerDetail.values()) {
            long numAlgorithms = 0;
            long numFormatsMax = 0;
            long numKeySizesMax = 0;
            long numKeysMax = 0;
            long total = 0;

            numAlgorithms = HMAC_ALGORITHMS.length;
            for (MacAlgorithm algo : HMAC_ALGORITHMS) {
                long numFormats =
                    SessionTicketMacFormat.generateFormats(detail, ticketBytesLength, algo.getSize()).size();
                var keySizes = DefaultKeys.getKeySizes(algo, detail);
                numFormatsMax = Math.max(numFormatsMax, numFormats);
                numKeySizesMax = Math.max(numKeySizesMax, keySizes.size());

                for (int keySize : keySizes) {
                    long numKeys = DefaultKeys.getKeys(keySize, detail).size();
                    total += numFormats * numKeys;
                    numKeysMax = Math.max(numKeysMax, numKeys);
                }

            }
            System.out.println(String.format("%-9s %2d %4d %1d %3d %10d %4.1f", detail, numAlgorithms, numFormatsMax,
                numKeySizesMax, numKeysMax, total, log2(total)));
        }
        System.out.println();
    }

    private static void checkPerformance(int ticketBytesLength) {
        // test performance
        List<Ticket> tickets =
            Arrays.asList(new TicketTls12(new byte[ticketBytesLength], new byte[32], Collections.emptyList()));
        for (ScannerDetail detail : ScannerDetail.values()) {
            if (detail == ScannerDetail.ALL)
                continue;
            long start = System.currentTimeMillis();
            analyzeDefaultStek(tickets, 16, detail);
            long middle = System.currentTimeMillis();
            analyzeDefaultHmacKey(tickets, detail);
            long stop = System.currentTimeMillis();
            System.out.println(String.format("%s\nEnc: %6.3fs\nMAC: %6.3fs", detail, (middle - start) / 1000f,
                (stop - middle) / 1000f));
            System.out.println();
        }

    }

    public static void main(String[] args) {
        int ticketBytesLength = 256;
        ticketBytesLength *= 10;
        checkNumberOfEncryptions(ticketBytesLength);
        checkNumberOfMacs(ticketBytesLength);
        checkPerformance(ticketBytesLength);
    }
}
