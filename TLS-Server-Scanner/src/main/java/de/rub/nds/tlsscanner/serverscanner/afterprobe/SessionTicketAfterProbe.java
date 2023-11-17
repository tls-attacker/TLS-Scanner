/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import de.rub.nds.scanner.core.afterprobe.AfterProbe;
import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.passive.ExtractedValueContainer;
import de.rub.nds.scanner.core.probe.result.DetailedResult;
import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.util.StaticTicketCrypto;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.passive.TrackableValueType;
import de.rub.nds.tlsscanner.core.util.ArrayUtil;
import de.rub.nds.tlsscanner.core.util.PrefixStatsUtil;
import de.rub.nds.tlsscanner.serverscanner.probe.result.VersionDependentResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.VersionDependentSummarizableResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.FoundDefaultHmacKey;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.FoundDefaultStek;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.FoundSecret;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.SessionTicketAfterStats;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.DefaultKeys;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionSecret;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketEncryptionFormat;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketMacFormat;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.TicketEncryptionAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.TicketHolder;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.TicketTls12;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionTicketAfterProbe extends AfterProbe<ServerReport> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final int MIN_ASCII_LENGTH = 8;

    private final ConfigSelector configSelector;

    public SessionTicketAfterProbe(ConfigSelector configSelector) {
        this.configSelector = configSelector;
    }

    @Override
    public void analyze(ServerReport report) {
        ExtractedValueContainer<TicketHolder> allTickets =
                report.getExtractedValueContainer(
                        TrackableValueType.SESSION_TICKET, TicketHolder.class);
        Map<ProtocolVersion, List<Ticket>> ticketMap = new EnumMap<>(ProtocolVersion.class);
        for (TicketHolder ticketHolder : allTickets.getExtractedValueList()) {
            ProtocolVersion protocolVersion = ticketHolder.getProtocolVersion();
            ticketMap
                    .computeIfAbsent(protocolVersion, k -> new LinkedList<>())
                    .addAll(ticketHolder);
        }

        ScannerDetail detail =
                configSelector.getScannerConfig().getExecutorConfig().getPostAnalysisDetail();

        VersionDependentResult<SessionTicketAfterStats> statistics = new VersionDependentResult<>();

        VersionDependentSummarizableResult<DetailedResult<FoundSecret>> unencryptedTicket =
                new VersionDependentSummarizableResult<>();
        VersionDependentSummarizableResult<DetailedResult<FoundSecret>> reusedKeystream =
                new VersionDependentSummarizableResult<>();

        VersionDependentSummarizableResult<DetailedResult<FoundDefaultStek>> defaultEncStek =
                new VersionDependentSummarizableResult<>();
        VersionDependentSummarizableResult<DetailedResult<FoundDefaultHmacKey>> defaultMacStek =
                new VersionDependentSummarizableResult<>();

        report.putResult(TlsAnalyzedProperty.STATISTICS_TICKET, statistics);

        report.putResult(TlsAnalyzedProperty.UNENCRYPTED_TICKET, unencryptedTicket);
        report.putResult(TlsAnalyzedProperty.REUSED_KEYSTREAM_TICKET, reusedKeystream);

        report.putResult(TlsAnalyzedProperty.DEFAULT_ENCRYPTION_KEY_TICKET, defaultEncStek);
        report.putResult(TlsAnalyzedProperty.DEFAULT_HMAC_KEY_TICKET, defaultMacStek);

        for (Entry<ProtocolVersion, List<Ticket>> entry : ticketMap.entrySet()) {
            ProtocolVersion version = entry.getKey();
            SessionTicketAfterStats versionStats = analyzeStatistics(entry.getValue());
            statistics.putResult(version, versionStats);
            List<Ticket> tickets = entry.getValue();

            unencryptedTicket.putResult(version, analyzeUnencryptedTicket(tickets));
            reusedKeystream.putResult(version, analyzeReusedKeyStream(tickets));

            defaultEncStek.putResult(
                    version, analyzeDefaultStek(tickets, versionStats.getKeyNameLength(), detail));
            defaultMacStek.putResult(version, analyzeDefaultHmacKey(tickets, detail));
        }
    }

    public static SessionTicketAfterStats analyzeStatistics(List<Ticket> tickets) {
        SessionTicketAfterStats result = new SessionTicketAfterStats();

        result.setTicketLengthOccurences(analyzeTicketLength(tickets));
        result.setKeyNameLength(analyzeKeyNameLength(tickets));
        // TODO: Analyze IV repetition/common bytes

        result.setAsciiStringsFound(analyzeAscii(tickets));

        return result;
    }

    private static Iterable<MacAlgorithm> getMacAlgorithms(ScannerDetail detail) {
        Set<MacAlgorithm> algorithms = new HashSet<>();
        if (detail.isGreaterEqualTo(ScannerDetail.QUICK)) {
            // observed during scan
            algorithms.add(MacAlgorithm.HMAC_SHA256);
            algorithms.add(MacAlgorithm.HMAC_SHA384);
        }
        if (detail.isGreaterEqualTo(ScannerDetail.NORMAL)) {
            // observed in implementations
            algorithms.add(MacAlgorithm.HMAC_SHA1);
        }
        if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            algorithms.add(MacAlgorithm.HMAC_SHA512);
            algorithms.add(MacAlgorithm.HMAC_MD5);
        }
        return algorithms;
    }

    private static Iterable<TicketEncryptionAlgorithm> getEncAlgorithms(ScannerDetail detail) {
        Set<TicketEncryptionAlgorithm> algorithms = new HashSet<>();
        if (detail.isGreaterEqualTo(ScannerDetail.QUICK)) {
            // observed during scan
            algorithms.add(TicketEncryptionAlgorithm.AES_128_CBC);
            algorithms.add(TicketEncryptionAlgorithm.AES_256_CBC);
        }
        if (detail.isGreaterEqualTo(ScannerDetail.NORMAL)) {
            // observed in implementations
            algorithms.add(TicketEncryptionAlgorithm.AES_128_GCM);
            algorithms.add(TicketEncryptionAlgorithm.AES_256_GCM);
            algorithms.add(TicketEncryptionAlgorithm.AES_128_CTR);
            algorithms.add(TicketEncryptionAlgorithm.AES_128_CCM);
            algorithms.add(TicketEncryptionAlgorithm.AES_256_CCM);
            algorithms.add(TicketEncryptionAlgorithm.CHACHA20_POLY1305);
        }
        if (detail.isGreaterEqualTo(ScannerDetail.DETAILED)) {
            return Arrays.asList(TicketEncryptionAlgorithm.values());
        }
        return algorithms;
    }

    /**
     * Get the lengths of the ticket. Returns a Map of lengths and occurences.
     *
     * @param tickets Tickets to analyze
     * @return Returns a Map of lengths and how often it occurred. The keys are the lengths. The
     *     values the occurences.
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
     * @param tickets Tickets to analyze
     * @return The most likely length of the key name
     */
    private static int analyzeKeyNameLength(List<Ticket> tickets) {
        Map<Integer, Integer> lengthToDivergences =
                PrefixStatsUtil.computePrefixDivergences(
                        tickets.stream()
                                .map(Ticket::getTicketBytesOriginal)
                                .collect(Collectors.toList()));
        // find prefix length with most divergences afterwards
        // this means we want the key with the highest value
        // This approach should solve two problems:
        // - the tickets randomly starting with the same byte (after the key name)
        // - hitting a load balancer/different servers
        Entry<Integer, Integer> lengthAndNumDivergences = null;
        for (Entry<Integer, Integer> item : lengthToDivergences.entrySet()) {
            LOGGER.debug("Depth, Divergences: {}, {}", item.getKey(), item.getValue());
            if (lengthAndNumDivergences == null
                    || lengthAndNumDivergences.getValue() < item.getValue()) {
                lengthAndNumDivergences = item;
            }
        }
        return lengthAndNumDivergences == null ? 0 : lengthAndNumDivergences.getKey();
    }

    private static boolean isAscii(byte b) {
        return b >= 0x20 && b <= 0x7F;
    }

    /**
     * Get ascii strings from the tickets. This finds substrings of consecutive ascii characters. It
     * stores all strings over MIN_ASCII_LENGTH (8 Bytes) and the longest string (useful if < 8B).
     *
     * @param tickets Tickets to analyze
     * @return List of ASCII-Strings found in the ticket.
     */
    private static List<String> analyzeAscii(List<Ticket> tickets) {
        String longestAsciiFound = "";
        List<String> strings = new ArrayList<>();
        for (Ticket ticket : tickets) {
            byte[] ticketBytes = ticket.getTicketBytesOriginal();

            // append a 0 byte: This way the last byte will not be within ascii -> the else branch
            // will be triggered
            // -> we do not need to repeat handling the end of the string after the for loop
            ticketBytes = Arrays.copyOf(ticketBytes, ticketBytes.length + 1);
            assert ticketBytes[ticketBytes.length - 1] == 0;

            int currentAsciiStart = 0;
            for (int i = 0; i < ticketBytes.length; i++) {
                byte b = ticketBytes[i];
                if (!isAscii(b)) {
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

    private static DetailedResult<FoundSecret> analyzeUnencryptedTicket(List<Ticket> tickets) {
        for (Ticket ticket : tickets) {
            FoundSecret foundSecret = ticket.checkContainsSecrets(ticket.getTicketBytesOriginal());
            if (foundSecret != null) {
                return DetailedResult.TRUE(foundSecret);
            }
        }
        return DetailedResult.FALSE();
    }

    private static DetailedResult<FoundDefaultStek> analyzeDefaultStek(
            List<Ticket> tickets, int keyNameLength, ScannerDetail detail) {
        // for ticket
        // for algorithm
        // for format
        // for key
        // try decrypt and find secret

        // minor todo: optimize to reduce "duplicate" decryptions
        // e.g. ECB and CBC modes only care about offsets of 0-15. 16 Is again equivalent to 0 (with
        // first block missing)
        for (Ticket ticket : tickets) {
            byte[] ticketBytes = ticket.getTicketBytesOriginal();
            for (TicketEncryptionAlgorithm algo : getEncAlgorithms(detail)) {
                for (SessionTicketEncryptionFormat format :
                        SessionTicketEncryptionFormat.generateFormats(
                                detail, ticketBytes.length, algo.ivNonceSize, keyNameLength)) {

                    byte[] iv = format.getIvNonce(ticketBytes);
                    byte[] ciphertext = format.getCiphertextTruncated(ticketBytes, algo.blockSize);

                    for (byte[] key : DefaultKeys.getKeys(algo.keySize, detail)) {
                        byte[] decState = algo.decryptIgnoringIntegrity(key, iv, ciphertext);
                        FoundSecret foundSecret = ticket.checkContainsSecrets(decState);
                        if (foundSecret != null) {
                            return DetailedResult.TRUE(
                                    new FoundDefaultStek(algo, format, key, foundSecret));
                        }
                    }
                }
            }
        }
        return DetailedResult.FALSE();
    }

    private static DetailedResult<FoundDefaultHmacKey> analyzeDefaultHmacKey(
            List<Ticket> tickets, ScannerDetail detail) {
        // for ticket
        // for algorithm
        // for format
        // for keysize
        // for key
        // check whether MAC is included (in non input range)
        for (Ticket ticket : tickets) {
            byte[] ticketBytes = ticket.getTicketBytesOriginal();

            for (MacAlgorithm algo : getMacAlgorithms(detail)) {
                for (SessionTicketMacFormat format :
                        SessionTicketMacFormat.generateFormats(
                                detail, ticketBytes.length, algo.getSize())) {
                    byte[] plaintext = format.getMacInput(ticketBytes);
                    byte[] prefix = format.getInputPrefix(ticketBytes);
                    byte[] suffix = format.getInputSuffix(ticketBytes);

                    for (int keySize : DefaultKeys.getKeySizes(algo, detail)) {
                        for (byte[] key : DefaultKeys.getKeys(keySize, detail)) {

                            try {
                                byte[] tag = StaticTicketCrypto.generateHMAC(algo, plaintext, key);
                                if (ArrayUtil.findSubarray(prefix, tag).isPresent()
                                        || ArrayUtil.findSubarray(suffix, tag).isPresent()) {

                                    return DetailedResult.TRUE(
                                            new FoundDefaultHmacKey(algo, format, key));
                                }
                            } catch (CryptoException e) {
                                throw new RuntimeException(e);
                            }
                        }
                    }
                }
            }
        }
        return DetailedResult.FALSE();
    }

    private static List<SessionSecret> xorSecrets(
            Ticket ticketA, Ticket ticketB, boolean skipSameSecrets) {
        List<SessionSecret> xoredSecrets = new LinkedList<>();
        for (SessionSecret secretA : ticketA.getSessionSecrets()) {
            for (SessionSecret secretB : ticketB.getSessionSecrets()) {
                if (secretA.secretType == secretB.secretType
                        && secretA.value.length == secretB.value.length) {
                    if (skipSameSecrets && Arrays.equals(secretA.value, secretB.value)) {
                        continue;
                    }
                    xoredSecrets.add(
                            new SessionSecret(
                                    secretA.secretType,
                                    ArrayUtil.xor(secretA.value, secretB.value)));
                }
            }
        }
        return xoredSecrets;
    }

    /**
     * Checks whether two tickets were encrypted using the same keystream (assuming XOR). For
     * example, this can happen if the IV/Nonce in CTR/GCM are reused.
     *
     * @param tickets Tickets to analyze
     */
    private static DetailedResult<FoundSecret> analyzeReusedKeyStream(List<Ticket> tickets) {
        for (int i = 0; i < tickets.size(); i++) {
            Ticket ticketA = tickets.get(i);
            for (int j = i + 1; j < tickets.size(); j++) {
                Ticket ticketB = tickets.get(j);
                byte[] xoredTickets =
                        ArrayUtil.xor(
                                ticketA.getTicketBytesOriginal(), ticketB.getTicketBytesOriginal());
                Ticket combinedSecrets =
                        new TicketTls12(null, null, xorSecrets(ticketA, ticketB, true));

                FoundSecret foundSecret = combinedSecrets.checkContainsSecrets(xoredTickets);
                if (foundSecret != null) {
                    return DetailedResult.TRUE(foundSecret);
                }
            }
        }
        return DetailedResult.FALSE();
    }
}
