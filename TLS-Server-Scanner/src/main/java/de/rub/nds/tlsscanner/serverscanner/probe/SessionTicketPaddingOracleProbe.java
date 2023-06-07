/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.attacks.general.Vector;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.attacks.padding.vector.FingerprintTaskVectorPair;
import de.rub.nds.tlsattacker.attacks.task.FingerPrintTask;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.leak.info.TestInfo;
import de.rub.nds.tlsscanner.serverscanner.leak.info.TicketPoLastByteTestInfo;
import de.rub.nds.tlsscanner.serverscanner.leak.info.TicketPoSecondByteTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketBaseProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketUtil;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.ModifiedTicket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketPoVector;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketPoVectorLast;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketPoVectorSecond;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.SessionTicketPaddingOracleProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.SessionTicketProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket.TicketPaddingOracleOffsetResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket.TicketPaddingOracleResult;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.ResponseCounter;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.VectorContainer;

public class SessionTicketPaddingOracleProbe extends SessionTicketBaseProbe {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final int INITIAL_ITERATIONS_LAST_BYTE = 2;
    private static final int ADDITIONAL_ITERATIONS_LAST_BYTE = 8;
    private static final int INITIAL_ITERATIONS_SECOND_BYTE = 2;
    private static final int ADDITIONAL_ITERATIONS_SECOND_BYTE = 2;

    // Offsets from the right for the IV of the Padding
    private static final Integer[] PADDING_IV_OFFSETS;

    // Target plaintext we want to have in the last byte that form a valid 1B padding
    private static final Byte[] TARGET_PLAINTEXTS_LAST_BYTE = { 1, 0 };

    // Possible plaintexts the last byte can have; i.e. all last bytes of all possible paddings
    private static final Byte[] POSSIBLE_PLAINTEXTS_LAST_BYTE;
    /**
     * All possible xor values we might want to xor the last byte with. That is, all values that cause the existing
     * padding to be transformed to a valid 1B padding.
     */
    private static final Byte[] XOR_VALUES_LAST_BYTE;

    // Array containing all possible byte values. Not strictly needed, but sometimes easier to read
    private static final Byte[] ALL_BYTES;

    static {
        List<Byte> plaintexts = new ArrayList<>(17);
        // assume possible padding schemes could have a 1 byte padding of 0x00 or 0x01
        // hence a 16B padding would be 0x0f or 0x10 respectively
        // Therefore we add 0 (0x00) through 16 (0x10) (inclusive) to the possible plaintexts
        for (int i = 0; i <= 16; i++) {
            plaintexts.add((byte) i);
        }
        POSSIBLE_PLAINTEXTS_LAST_BYTE = plaintexts.toArray(new Byte[0]);

        Set<Byte> xorValues = new HashSet<>();
        for (byte targetPlain : TARGET_PLAINTEXTS_LAST_BYTE) {
            for (byte assumedPlain : POSSIBLE_PLAINTEXTS_LAST_BYTE) {
                xorValues.add((byte) (targetPlain ^ assumedPlain));
            }
        }
        XOR_VALUES_LAST_BYTE = xorValues.toArray(new Byte[0]);

        List<Byte> allBytes = new ArrayList<>(256);
        for (int i = Byte.MIN_VALUE; i <= Byte.MAX_VALUE; i++) {
            allBytes.add((byte) i);
        }
        ALL_BYTES = allBytes.toArray(new Byte[0]);

        Set<Integer> offsets = new HashSet<>();
        for (int blockSize : new int[] { 8, 16 }) {
            for (int suffix : new int[] { 0, 16, 20, 28, 32, 48, 64 }) {
                offsets.add(blockSize + suffix);
            }
        }
        PADDING_IV_OFFSETS = offsets.toArray(new Integer[0]);
    }

    public SessionTicketPaddingOracleProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.SESSION_TICKET_PADDING_ORACLE, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        SessionTicketPaddingOracleProbeResult overallResult = new SessionTicketPaddingOracleProbeResult();
        for (ProtocolVersion version : versionsToTest) {
            try {
                overallResult.putResult(checkPaddingOracle(version));
            } catch (Exception E) {
                LOGGER.error("Could not scan SessionTickets Padding Oracle for version {}", version, E);
                overallResult.putResult(new TicketPaddingOracleResult(version, TestResult.ERROR_DURING_TEST));
                if (E.getCause() instanceof InterruptedException) {
                    LOGGER.error("Timeout on {}", getProbeName());
                    throw E;
                }
            }
        }
        return overallResult;
    }

    private TicketPaddingOracleResult checkPaddingOracle(ProtocolVersion version) {
        State ticketState = prepareInitialHandshake(version);
        executeState(ticketState);
        if (!initialHandshakeSuccessful(ticketState)) {
            LOGGER.warn("Initial Handshake failed {}", version);
            return new TicketPaddingOracleResult(version, TestResult.ERROR_DURING_TEST);
        }
        Ticket originalTicket = SessionTicketUtil.getSessionTickets(ticketState).get(0);

        List<TicketPaddingOracleOffsetResult> offsetResults = new ArrayList<>(PADDING_IV_OFFSETS.length);
        boolean breakEarly = false;
        for (Integer offset : PADDING_IV_OFFSETS) {
            if (offset + 2 > originalTicket.getTicketBytesOriginal().length) {
                // do not check ticket if the offset (+1 due to prefixXorValue, +1 due to second byte) is larger than
                // the ticket is long
                continue;
            }
            TicketPoLastByteTestInfo lastByteTestInfo = new TicketPoLastByteTestInfo(version, offset);
            List<TicketPoVector> lastVectors = createPaddingVectorsLastByte(offset);

            InformationLeakTest<TicketPoLastByteTestInfo> lastByteLeakTest = createInformationLeakTest(lastByteTestInfo,
                version, lastVectors, originalTicket, INITIAL_ITERATIONS_LAST_BYTE, ADDITIONAL_ITERATIONS_LAST_BYTE);

            List<InformationLeakTest<TicketPoSecondByteTestInfo>> secondByteLeakTests = new ArrayList<>();

            if (lastByteLeakTest.isSignificantDistinctAnswers()) {
                for (VectorResponse response : getRareResponses(lastByteLeakTest, 2)) {
                    TicketPoVectorLast lastVector = (TicketPoVectorLast) response.getVector();
                    TicketPoSecondByteTestInfo secondByteTestInfo = new TicketPoSecondByteTestInfo(version, lastVector);
                    List<TicketPoVector> secondVectors = createPaddingVectorsSecondByte(offset, lastVector.xorValue);

                    InformationLeakTest<TicketPoSecondByteTestInfo> secondByteLeakTest =
                        createInformationLeakTest(secondByteTestInfo, version, secondVectors, originalTicket,
                            INITIAL_ITERATIONS_SECOND_BYTE, ADDITIONAL_ITERATIONS_SECOND_BYTE);

                    secondByteLeakTests.add(secondByteLeakTest);
                    if (!scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.ALL)
                        && secondByteLeakTest.isSignificantDistinctAnswers()
                        && !getRareResponses(secondByteLeakTest, 1).isEmpty()) {
                        // break early if we found a unique response for the second byte
                        // we do not break early if the scanner is set to detail ALL
                        breakEarly = true;
                        break;
                    }
                }

            }

            offsetResults.add(new TicketPaddingOracleOffsetResult(lastByteLeakTest, secondByteLeakTests));
            if (breakEarly) {
                break;
            }
        }

        return new TicketPaddingOracleResult(version, offsetResults);
    }

    public static <T extends TestInfo> List<VectorResponse> getRareResponses(InformationLeakTest<T> informationLeakTest,
        int mostOccurences) {

        Map<ResponseFingerprint, List<Vector>> map = new HashMap<>();
        for (VectorContainer container : informationLeakTest.getVectorContainerList()) {
            for (ResponseCounter counter : container.getDistinctResponsesCounterList()) {
                map.computeIfAbsent(counter.getFingerprint(), k -> new ArrayList<>());
                map.get(counter.getFingerprint()).add(container.getVector());
            }
        }

        // find rare fingerprints + vectors
        List<VectorResponse> ret = new ArrayList<>();
        for (var entry : map.entrySet()) {
            ResponseFingerprint fingerprint = entry.getKey();
            List<Vector> vectors = entry.getValue();
            if (vectors.size() <= mostOccurences) {
                for (Vector vector : vectors) {
                    ret.add(new VectorResponse(vector, fingerprint));
                }
            }
        }
        return ret;
    }

    private List<TicketPoVector> createPaddingVectorsLastByte(Integer paddingIvOffset) {
        List<TicketPoVector> vectorList = new ArrayList<>(XOR_VALUES_LAST_BYTE.length);

        for (Byte xorValue : XOR_VALUES_LAST_BYTE) {
            TicketPoVectorLast vector = new TicketPoVectorLast(paddingIvOffset, xorValue);
            vectorList.add(vector);
        }

        return vectorList;
    }

    private List<TicketPoVector> createPaddingVectorsSecondByte(Integer paddingIvOffset, Byte previousXorValue) {
        List<TicketPoVector> vectorList = new ArrayList<>(ALL_BYTES.length * TARGET_PLAINTEXTS_LAST_BYTE.length);

        for (Byte oldTargetPlaintext : TARGET_PLAINTEXTS_LAST_BYTE) {
            Byte newTargetPlaintext = (byte) (oldTargetPlaintext + 1);
            Byte lastAssumedPlaintext = (byte) (previousXorValue ^ oldTargetPlaintext);
            Byte newLastXorValue = (byte) (lastAssumedPlaintext ^ newTargetPlaintext);
            for (Byte xorValue : ALL_BYTES) {
                Byte assumedSecondPlaintext = (byte) (xorValue ^ newTargetPlaintext);
                TicketPoVectorSecond vector = new TicketPoVectorSecond(paddingIvOffset, newLastXorValue,
                    lastAssumedPlaintext, xorValue, assumedSecondPlaintext);
                vectorList.add(vector);
            }
        }

        return vectorList;
    }

    private <I extends TestInfo> InformationLeakTest<I> createInformationLeakTest(I testInfo, ProtocolVersion version,
        List<TicketPoVector> vectors, Ticket originalTicket, int initialIterations, int additionalIterations) {
        var responses = createVectorResponseList(version, vectors, originalTicket, initialIterations);
        var informationLeakTest = new InformationLeakTest<>(testInfo, responses);

        if (informationLeakTest.isDistinctAnswers()) {
            // TODO reduce vectors for second byte
            responses = createVectorResponseList(version, vectors, originalTicket, additionalIterations);
            informationLeakTest.extendTestWithVectorResponses(responses);
        }
        return informationLeakTest;
    }

    private List<VectorResponse> createVectorResponseList(ProtocolVersion version, List<TicketPoVector> vectors,
        Ticket originalTicket, int iterationsPerVector) {

        List<FingerprintTaskVectorPair<TicketPoVector>> taskList = new ArrayList<>(vectors.size());
        for (TicketPoVector vector : vectors) {
            for (int i = 0; i < iterationsPerVector; i++) {
                ModifiedTicket ticket = vector.createTicket(originalTicket, (byte) (0x42 + i));
                FingerPrintTask task =
                    prepareResumptionFingerprintTask(version, ticket, false, HandshakeMessageType.SERVER_HELLO);
                taskList.add(new FingerprintTaskVectorPair<>(task, vector));
            }
        }

        getParallelExecutor().bulkExecuteTasks(
            taskList.stream().map(FingerprintTaskVectorPair::getFingerPrintTask).collect(Collectors.toList()));

        return taskList.stream().map(FingerprintTaskVectorPair::toVectorResponse).collect(Collectors.toList());
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new SessionTicketPaddingOracleProbeResult();
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (!super.canBeExecuted(report)) {
            return false;
        }
        return report.getResult(AnalyzedProperty.ISSUES_TICKET) == TestResult.TRUE;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        super.adjustConfig(report);
        SessionTicketProbeResult probeResult = report.getSessionTicketProbeResult();
        for (ProtocolVersion version : versionsToTest.toArray(new ProtocolVersion[0])) {
            if (probeResult.getResult(version).getIssuesTickets() != TestResult.TRUE) {
                versionsToTest.remove(version);
            }
        }
        // only keep 1.3 and highest pre 1.3 version
        // we sort the versions descending (without 1.3)
        // and remove all but the first from the versions to test
        List<ProtocolVersion> sortedVersions = new ArrayList<>(versionsToTest);
        sortedVersions.remove(ProtocolVersion.TLS13);
        if (!sortedVersions.isEmpty()) {
            ProtocolVersion.sort(sortedVersions, false);
            sortedVersions.remove(0);
            versionsToTest.removeAll(sortedVersions);
        }
    }
}
