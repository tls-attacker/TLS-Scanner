/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.task.FingerPrintTask;
import de.rub.nds.tlsscanner.core.task.FingerprintTaskVectorPair;
import de.rub.nds.tlsscanner.core.vector.Vector;
import de.rub.nds.tlsscanner.core.vector.VectorResponse;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.core.vector.statistics.ResponseCounter;
import de.rub.nds.tlsscanner.core.vector.statistics.TestInfo;
import de.rub.nds.tlsscanner.core.vector.statistics.VectorContainer;
import de.rub.nds.tlsscanner.serverscanner.leak.TicketPaddingOracleLastByteTestInfo;
import de.rub.nds.tlsscanner.serverscanner.leak.TicketPaddingOracleSecondByteTestInfo;
import de.rub.nds.tlsscanner.serverscanner.probe.result.VersionDependentSummarizableResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.TicketPaddingOracleOffsetResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.TicketPaddingOracleResult;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketBaseProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketUtil;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.ModifiedTicket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketPaddingOracleVector;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketPaddingOracleVectorLast;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketPaddingOracleVectorSecond;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionTicketPaddingOracleProbe extends SessionTicketBaseProbe {
    private static final Logger LOGGER = LogManager.getLogger();

    // region static init
    /**
     * minimum secret size is 32 byte. The ticket should at least be large enough to contain this
     */
    private static final int MINIMUM_TICKET_CONTENT_LENGTH = 32;

    private static final int INITIAL_ITERATIONS_LAST_BYTE = 2;
    private static final int ADDITIONAL_ITERATIONS_LAST_BYTE = 8;
    private static final int INITIAL_ITERATIONS_SECOND_BYTE = 2;
    private static final int ADDITIONAL_ITERATIONS_SECOND_BYTE = 2;

    // Offsets from the right for the IV of the Padding
    private static final Integer[] PADDING_IV_OFFSETS;

    // Target plaintext we want to have in the last byte that form a valid 1B padding
    private static final Byte[] TARGET_PLAINTEXTS_LAST_BYTE = {1, 0};

    // Possible plaintexts the last byte can have; i.e. all last bytes of all possible paddings
    private static final Byte[] POSSIBLE_PLAINTEXTS_LAST_BYTE;
    /**
     * All possible xor values we might want to xor the last byte with. That is, all values that
     * cause the existing padding to be transformed to a valid 1B padding.
     */
    private static final Byte[] XOR_VALUES_LAST_BYTE;

    // Array containing all possible byte values. Not strictly needed, but sometimes easier to read
    private static final Byte[] ALL_BYTES;

    // "init" functions to initialize static final fields
    private static Byte[] initPossiblePlaintextsLastByte() {
        List<Byte> plaintexts = new ArrayList<>(17);
        // Assume possible padding schemes could have a 1 byte padding of 0x00 or 0x01
        // (cf.TARGET_PLAINTEXTS_LAST_BYTE). Hence, a 16B padding would be 0x0f or 0x10
        // respectively. Therefore, we add 0 (0x00) through 16 (0x10) (inclusive) to the possible
        // plaintexts.

        for (int i = 0; i <= 16; i++) {
            plaintexts.add((byte) i);
        }
        return plaintexts.toArray(new Byte[0]);
    }

    private static Byte[] initXorValuesLastByte() {
        Set<Byte> xorValues = new HashSet<>();
        for (byte targetPlain : TARGET_PLAINTEXTS_LAST_BYTE) {
            for (byte assumedPlain : POSSIBLE_PLAINTEXTS_LAST_BYTE) {
                xorValues.add((byte) (targetPlain ^ assumedPlain));
            }
        }

        return xorValues.toArray(new Byte[0]);
    }

    private static Byte[] initAllBytes() {
        List<Byte> allBytes = new ArrayList<>(256);
        for (int i = Byte.MIN_VALUE; i <= Byte.MAX_VALUE; i++) {
            allBytes.add((byte) i);
        }

        return allBytes.toArray(new Byte[0]);
    }

    private static Integer[] initPaddingIvOffsets() {
        Set<Integer> offsets = new HashSet<>();
        for (int blockSize : new int[] {8, 16}) {
            for (int suffix : new int[] {0, 16, 20, 28, 32, 48, 64}) {
                offsets.add(blockSize + suffix);
            }
        }

        return offsets.toArray(new Integer[0]);
    }

    static {
        POSSIBLE_PLAINTEXTS_LAST_BYTE = initPossiblePlaintextsLastByte();
        XOR_VALUES_LAST_BYTE = initXorValuesLastByte();
        ALL_BYTES = initAllBytes();
        PADDING_IV_OFFSETS = initPaddingIvOffsets();
    }
    // endregion

    private VersionDependentSummarizableResult<TicketPaddingOracleResult> overallResult;

    public SessionTicketPaddingOracleProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, configSelector, TlsProbeType.SESSION_TICKET_PADDING_ORACLE);
        register(TlsAnalyzedProperty.PADDING_ORACLE_TICKET);
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.PADDING_ORACLE_TICKET, overallResult);
    }

    @Override
    public void executeTest() {
        overallResult = new VersionDependentSummarizableResult<>();
        for (ProtocolVersion version : versionsToTest) {
            try {
                overallResult.putResult(version, checkPaddingOracle(version));
            } catch (Exception E) {
                LOGGER.error(
                        "Could not scan SessionTickets Padding Oracle for version {}", version, E);
                overallResult.putResult(
                        version, new TicketPaddingOracleResult(TestResults.ERROR_DURING_TEST));
                if (E.getCause() instanceof InterruptedException) {
                    LOGGER.error("Timeout on {}", getProbeName());
                    throw E;
                }
            }
        }
    }

    private boolean shouldCheckOffset(int offset, int ticketLength) {
        return offset + MINIMUM_TICKET_CONTENT_LENGTH <= ticketLength;
    }

    /**
     * Check whether we found a significant and unique result.
     *
     * @param secondByteLeakTest The leak test that should be checked.
     * @return Whether we have found a statistically relevant result, and we have found a response
     *     that only occurred once. The unique response most likely corresponds to the correct
     *     padding.
     */
    private boolean foundDefinitiveResult(
            InformationLeakTest<TicketPaddingOracleSecondByteTestInfo> secondByteLeakTest) {
        return secondByteLeakTest.isSignificantDistinctAnswers()
                && !getRareResponses(secondByteLeakTest, 1).isEmpty();
    }

    private TicketPaddingOracleResult checkPaddingOracle(ProtocolVersion version) {
        State ticketState = prepareInitialHandshake(version);
        executeState(ticketState);
        if (!initialHandshakeSuccessful(ticketState)) {
            LOGGER.warn("Initial Handshake failed {}", version);
            return new TicketPaddingOracleResult(TestResults.ERROR_DURING_TEST);
        }
        Ticket originalTicket = SessionTicketUtil.getSessionTickets(ticketState).get(0);

        List<TicketPaddingOracleOffsetResult> offsetResults =
                new ArrayList<>(PADDING_IV_OFFSETS.length);
        boolean breakEarly = false;
        LOGGER.debug("Starting to evaluate version {}", version);
        for (Integer offset : PADDING_IV_OFFSETS) {
            if (!shouldCheckOffset(offset, originalTicket.getTicketBytesOriginal().length)) {
                continue;
            }
            TicketPaddingOracleLastByteTestInfo lastByteTestInfo =
                    new TicketPaddingOracleLastByteTestInfo(version, offset);
            List<TicketPaddingOracleVector> lastVectors = createPaddingVectorsLastByte(offset);

            LOGGER.debug("Checking Offset {} with {} vectors", offset, lastVectors.size());

            InformationLeakTest<TicketPaddingOracleLastByteTestInfo> lastByteLeakTest =
                    createInformationLeakTest(
                            lastByteTestInfo,
                            version,
                            lastVectors,
                            originalTicket,
                            INITIAL_ITERATIONS_LAST_BYTE,
                            ADDITIONAL_ITERATIONS_LAST_BYTE);

            List<InformationLeakTest<TicketPaddingOracleSecondByteTestInfo>> secondByteLeakTests =
                    new ArrayList<>();

            if (lastByteLeakTest.isSignificantDistinctAnswers()) {
                List<VectorResponse> rareResponses = getRareResponses(lastByteLeakTest, 2);
                LOGGER.debug(
                        "At Offset {} found significant difference with {} rare response(s)",
                        offset,
                        rareResponses.size());
                for (VectorResponse response : rareResponses) {
                    TicketPaddingOracleVectorLast lastVector =
                            (TicketPaddingOracleVectorLast) response.getVector();
                    TicketPaddingOracleSecondByteTestInfo secondByteTestInfo =
                            new TicketPaddingOracleSecondByteTestInfo(version, lastVector);
                    List<TicketPaddingOracleVector> secondVectors =
                            createPaddingVectorsSecondByte(offset, lastVector.xorValue);

                    LOGGER.debug(
                            "At Offset {} checking further {} vectors",
                            offset,
                            secondVectors.size());

                    InformationLeakTest<TicketPaddingOracleSecondByteTestInfo> secondByteLeakTest =
                            createInformationLeakTest(
                                    secondByteTestInfo,
                                    version,
                                    secondVectors,
                                    originalTicket,
                                    INITIAL_ITERATIONS_SECOND_BYTE,
                                    ADDITIONAL_ITERATIONS_SECOND_BYTE);

                    secondByteLeakTests.add(secondByteLeakTest);
                    if (!configSelector
                                    .getScannerConfig()
                                    .getExecutorConfig()
                                    .getScanDetail()
                                    .isGreaterEqualTo(ScannerDetail.ALL)
                            && foundDefinitiveResult(secondByteLeakTest)) {
                        // we do not break early if the scanner is set to detail ALL
                        breakEarly = true;
                        break;
                    }
                }
            }

            offsetResults.add(
                    new TicketPaddingOracleOffsetResult(lastByteLeakTest, secondByteLeakTests));
            if (breakEarly) {
                break;
            }
        }

        return new TicketPaddingOracleResult(offsetResults);
    }

    public static <T extends TestInfo> List<VectorResponse> getRareResponses(
            InformationLeakTest<T> informationLeakTest, int mostOccurrences) {
        Map<ResponseFingerprint, List<Vector>> map = new HashMap<>();
        for (VectorContainer container : informationLeakTest.getVectorContainerList()) {
            for (ResponseCounter counter : container.getDistinctResponsesCounterList()) {
                map.computeIfAbsent(counter.getFingerprint(), k -> new ArrayList<>());
                map.get(counter.getFingerprint()).add(container.getVector());
            }
        }

        List<VectorResponse> ret = new ArrayList<>();
        for (var entry : map.entrySet()) {
            ResponseFingerprint fingerprint = entry.getKey();
            List<Vector> vectors = entry.getValue();
            if (vectors.size() <= mostOccurrences) {
                for (Vector vector : vectors) {
                    ret.add(new VectorResponse(vector, fingerprint));
                }
            }
        }
        return ret;
    }

    private List<TicketPaddingOracleVector> createPaddingVectorsLastByte(Integer paddingIvOffset) {
        List<TicketPaddingOracleVector> vectorList = new ArrayList<>(XOR_VALUES_LAST_BYTE.length);

        for (Byte xorValue : XOR_VALUES_LAST_BYTE) {
            TicketPaddingOracleVectorLast vector =
                    new TicketPaddingOracleVectorLast(paddingIvOffset, xorValue);
            vectorList.add(vector);
        }

        return vectorList;
    }

    private List<TicketPaddingOracleVector> createPaddingVectorsSecondByte(
            Integer paddingIvOffset, Byte previousXorValue) {
        List<TicketPaddingOracleVector> vectorList =
                new ArrayList<>(ALL_BYTES.length * TARGET_PLAINTEXTS_LAST_BYTE.length);

        for (Byte oldTargetPlaintext : TARGET_PLAINTEXTS_LAST_BYTE) {
            Byte newTargetPlaintext = (byte) (oldTargetPlaintext + 1);
            Byte lastAssumedPlaintext = (byte) (previousXorValue ^ oldTargetPlaintext);
            Byte newLastXorValue = (byte) (lastAssumedPlaintext ^ newTargetPlaintext);
            for (Byte xorValue : ALL_BYTES) {
                Byte assumedSecondPlaintext = (byte) (xorValue ^ newTargetPlaintext);
                TicketPaddingOracleVectorSecond vector =
                        new TicketPaddingOracleVectorSecond(
                                paddingIvOffset,
                                newLastXorValue,
                                lastAssumedPlaintext,
                                xorValue,
                                assumedSecondPlaintext);
                vectorList.add(vector);
            }
        }

        return vectorList;
    }

    private <I extends TestInfo> InformationLeakTest<I> createInformationLeakTest(
            I testInfo,
            ProtocolVersion version,
            List<TicketPaddingOracleVector> vectors,
            Ticket originalTicket,
            int initialIterations,
            int additionalIterations) {
        List<VectorResponse> responses =
                createVectorResponseList(version, vectors, originalTicket, initialIterations);
        InformationLeakTest<I> informationLeakTest = new InformationLeakTest<>(testInfo, responses);

        if (informationLeakTest.isDistinctAnswers()) {
            LOGGER.debug("Found distinct answers - fetching more responses to check significance");
            // TODO reduce vectors for second byte
            responses =
                    createVectorResponseList(
                            version, vectors, originalTicket, additionalIterations);
            informationLeakTest.extendTestWithVectorResponses(responses);
        }
        return informationLeakTest;
    }

    private List<VectorResponse> createVectorResponseList(
            ProtocolVersion version,
            List<TicketPaddingOracleVector> vectors,
            Ticket originalTicket,
            int iterationsPerVector) {

        List<FingerprintTaskVectorPair<TicketPaddingOracleVector>> taskList =
                new ArrayList<>(vectors.size() * iterationsPerVector);
        for (TicketPaddingOracleVector vector : vectors) {
            for (int i = 0; i < iterationsPerVector; i++) {
                ModifiedTicket ticket = vector.createTicket(originalTicket, (byte) (0x42 + i));
                FingerPrintTask task =
                        prepareResumptionFingerprintTask(
                                version, ticket, false, HandshakeMessageType.SERVER_HELLO);
                taskList.add(new FingerprintTaskVectorPair<>(task, vector));
            }
        }

        getParallelExecutor()
                .bulkExecuteTasks(
                        taskList.stream()
                                .map(FingerprintTaskVectorPair::getFingerPrintTask)
                                .collect(Collectors.toList()));

        return taskList.stream()
                .map(FingerprintTaskVectorPair::toVectorResponse)
                .collect(Collectors.toList());
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return super.getRequirements().and(REQ_SUPPORTS_RESUMPTION);
    }
}
