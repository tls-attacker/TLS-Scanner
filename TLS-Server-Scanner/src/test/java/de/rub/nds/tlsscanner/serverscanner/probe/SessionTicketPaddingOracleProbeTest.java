/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertFalse;

import de.rub.nds.scanner.core.probe.result.ListResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.session.TicketSession;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.task.ITask;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.task.FingerPrintTask;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.result.VersionDependentSummarizableResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.VersionDependentTestResults;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.TicketPaddingOracleResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.jupiter.api.Tag;
import org.mockito.Mockito;

public class SessionTicketPaddingOracleProbeTest {
    private static List<OracleParameters> PARAMETERS;
    private static final int MINIMUM_TICKET_CONTENT_LENGTH = 32;

    public SessionTicketPaddingOracleProbeTest() {}

    @BeforeClass
    public static void beforeClass() {
        PARAMETERS = new ArrayList<>();
        // prefix+content+mac
        PARAMETERS.add(
                new OracleParameters(
                        16,
                        MINIMUM_TICKET_CONTENT_LENGTH,
                        16,
                        16,
                        PaddingType.CONSTANT_START_AT_ONE));
        // prefix+content
        PARAMETERS.add(
                new OracleParameters(
                        16,
                        MINIMUM_TICKET_CONTENT_LENGTH,
                        0,
                        16,
                        PaddingType.CONSTANT_START_AT_ONE));
        // just content
        PARAMETERS.add(
                new OracleParameters(
                        0,
                        MINIMUM_TICKET_CONTENT_LENGTH,
                        0,
                        16,
                        PaddingType.CONSTANT_START_AT_ONE));
        // no mac, different padding lengths
        for (int i = 0; i < 16; i++) {
            PARAMETERS.add(
                    new OracleParameters(
                            0,
                            MINIMUM_TICKET_CONTENT_LENGTH + i,
                            0,
                            16,
                            PaddingType.CONSTANT_START_AT_ONE));
        }
        // no mac, different padding lengths, not aligned with blocks
        for (int i = 0; i < 16; i++) {
            PARAMETERS.add(
                    new OracleParameters(
                            7,
                            MINIMUM_TICKET_CONTENT_LENGTH + i,
                            0,
                            16,
                            PaddingType.CONSTANT_START_AT_ONE));
        }

        // smaller blocksize
        PARAMETERS.add(
                new OracleParameters(
                        8,
                        MINIMUM_TICKET_CONTENT_LENGTH,
                        20,
                        8,
                        PaddingType.CONSTANT_START_AT_ONE));
        PARAMETERS.add(
                new OracleParameters(
                        3,
                        MINIMUM_TICKET_CONTENT_LENGTH + 8 + 5,
                        0,
                        8,
                        PaddingType.CONSTANT_START_AT_ONE));
        PARAMETERS.add(
                new OracleParameters(
                        1,
                        MINIMUM_TICKET_CONTENT_LENGTH + 8 + 7,
                        0,
                        8,
                        PaddingType.CONSTANT_START_AT_ONE));

        // different mac sizes, not aligned with blocks, different padding
        for (int macSize : new int[] {0, 16, 20, 28, 32, 48, 64}) {
            PARAMETERS.add(
                    new OracleParameters(
                            0,
                            MINIMUM_TICKET_CONTENT_LENGTH + 10,
                            macSize,
                            16,
                            PaddingType.CONSTANT_START_AT_ZERO));
        }
        // different padding
        PARAMETERS.add(
                new OracleParameters(
                        3,
                        MINIMUM_TICKET_CONTENT_LENGTH + 10,
                        0,
                        16,
                        PaddingType.COUNTING_UP_START_AT_ZERO));
    }

    @Test
    @Tag(TestCategories.SLOW_TEST)
    public void testNoOracle() {
        // takes ~120s
        for (OracleParameters parameters : PARAMETERS) {
            NoOracleExecutor executor = new NoOracleExecutor(parameters);
            var result = runProbe(executor);
            assertEquals(
                    parameters + " resulted in wrong result",
                    TestResults.FALSE,
                    result.getOverallResult());
        }
    }

    @Test
    @Tag(TestCategories.SLOW_TEST)
    public void testOracle() {
        // takes ages (a bit over 30m for me...)
        for (OracleParameters parameters : PARAMETERS) {
            var result = runProbe(new OracleExecutor(parameters));
            assertEquals(
                    parameters + " resulted in wrong result",
                    TestResults.TRUE,
                    result.getOverallResult());
        }
    }

    @Test
    public void testNoOracleFast() {
        // takes ~10s
        OracleParameters parameters = PARAMETERS.get(0);
        var result = runProbe(new NoOracleExecutor(parameters));
        assertEquals(
                parameters + " resulted in wrong result",
                TestResults.FALSE,
                result.getOverallResult());
    }

    @Test
    public void testOracleFast() {
        // takes ~50s
        OracleParameters parameters = PARAMETERS.get(0);
        var result = runProbe(new OracleExecutor(parameters));
        assertEquals(
                parameters + " resulted in wrong result",
                TestResults.TRUE,
                result.getOverallResult());
    }

    public TicketPaddingOracleResult runProbe(OracleExecutorBase executor) {
        final ProtocolVersion version = ProtocolVersion.TLS12;
        final List<CipherSuite> suites =
                Arrays.asList(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);

        // prepare report
        ServerReport report = new ServerReport("foohost", -1);
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS,
                new ListResult<>(
                        TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS, Arrays.asList(version)));
        report.putResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES, new HashSet<>(suites));
        VersionDependentTestResults issuesTickets = new VersionDependentTestResults();
        issuesTickets.putResult(version, TestResults.TRUE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_EXTENSION, issuesTickets);

        // prepare probe
        executor.reset();
        ServerScannerConfig config = new ServerScannerConfig(new GeneralDelegate());
        config.getClientDelegate().setHost("foohost");
        ConfigSelector configSelector = new DummyConfigSelector(config, executor);
        SessionTicketPaddingOracleProbe probe =
                new SessionTicketPaddingOracleProbe(configSelector, executor);

        // run probe
        probe.adjustConfig(report);
        probe.executeTest();
        probe.merge(report);

        // return result
        VersionDependentSummarizableResult<TicketPaddingOracleResult> result =
                (VersionDependentSummarizableResult<TicketPaddingOracleResult>)
                        report.getResult(TlsAnalyzedProperty.PADDING_ORACLE_TICKET);
        return result.getResult(ProtocolVersion.TLS12);
    }

    private enum PaddingType {
        CONSTANT_START_AT_ZERO,
        CONSTANT_START_AT_ONE,
        COUNTING_UP_START_AT_ZERO;

        public byte[] create(byte length) {
            byte[] ret = new byte[length];
            switch (this) {
                case CONSTANT_START_AT_ZERO:
                    Arrays.fill(ret, (byte) (length - 1));
                    break;
                case CONSTANT_START_AT_ONE:
                    Arrays.fill(ret, length);
                    break;
                case COUNTING_UP_START_AT_ZERO:
                    for (byte i = 0; i < length; i++) {
                        ret[i] = i;
                    }
                    break;
            }
            return ret;
        }

        public int getPaddingLength(byte[] array, int maxLength) {
            byte lastPaddingByte = array[array.length - 1];
            int expectedPaddingLength;
            switch (this) {
                case CONSTANT_START_AT_ZERO:
                    expectedPaddingLength = lastPaddingByte + 1;
                    break;
                case CONSTANT_START_AT_ONE:
                    expectedPaddingLength = lastPaddingByte;
                    break;
                case COUNTING_UP_START_AT_ZERO:
                    expectedPaddingLength = lastPaddingByte + 1;
                    break;
                default:
                    throw new UnsupportedOperationException("Unknown padding type");
            }
            if (expectedPaddingLength > maxLength || expectedPaddingLength < 1) {
                return -1;
            }

            byte[] validPadding = create((byte) expectedPaddingLength);
            for (int i = 1; i <= expectedPaddingLength; i++) {
                byte byteToCheck = array[array.length - i];
                byte expectedByte = validPadding[validPadding.length - i];
                if (byteToCheck != expectedByte) {
                    return -i;
                }
            }
            return expectedPaddingLength;
        }
    }

    private static class OracleParameters {
        // prefix before the content
        public final int prefixSize;
        // length of the actual content
        public final int contentLength;
        // initial length of the applied padding
        public final byte initialPaddingSize;
        // suffix, e.g. mac
        public final int suffixSize;
        public final int blockSize;
        public final PaddingType paddingType;

        public OracleParameters(
                int prefixSize,
                int contentLength,
                int suffixSize,
                int blockSize,
                PaddingType paddingType) {
            if (contentLength < 32) {
                throw new IllegalArgumentException(
                        "content must contain at least 32B for a secret");
            }
            this.prefixSize = prefixSize;
            this.contentLength = contentLength;
            int requiredPadding = blockSize - (contentLength % blockSize);
            if (requiredPadding <= 0 || requiredPadding > blockSize) {
                throw new RuntimeException("Internal error - padding length out of range");
            }
            this.initialPaddingSize = (byte) requiredPadding;
            this.suffixSize = suffixSize;
            this.blockSize = blockSize;
            this.paddingType = paddingType;
        }

        @Override
        public String toString() {
            return String.format(
                    "{prefixSize=%d, contentLength=%d, initialPaddingSize=%d, suffixSize=%d, blockSize=%d, paddingType=%s}",
                    prefixSize,
                    contentLength,
                    initialPaddingSize,
                    suffixSize,
                    blockSize,
                    paddingType);
        }
    }

    private abstract static class OracleExecutorBase extends ParallelExecutor {
        protected final ResponseFingerprint fingerprintAbortConnection,
                fingerprintIgnoreOrNoTicket,
                fingerprintUseTicket;

        public final OracleParameters params;

        public byte[] originalTicket = null;
        private final Field fingerprintField;

        public OracleExecutorBase(OracleParameters parameters) {
            super(
                    1,
                    0,
                    new ThreadPoolExecutor(1, 1, 5, TimeUnit.MINUTES, new LinkedBlockingDeque<>()));
            this.params = parameters;

            List<Record> recordList = new ArrayList<>();
            fingerprintAbortConnection =
                    new ResponseFingerprint(Arrays.asList(), recordList, SocketState.IO_EXCEPTION);
            fingerprintIgnoreOrNoTicket =
                    new ResponseFingerprint(
                            Arrays.asList(
                                    new ServerHelloMessage(),
                                    new CertificateMessage(),
                                    new ServerHelloDoneMessage()),
                            recordList,
                            SocketState.DATA_AVAILABLE);
            fingerprintUseTicket =
                    new ResponseFingerprint(
                            Arrays.asList(new ServerHelloMessage(), new ServerHelloDoneMessage()),
                            recordList,
                            SocketState.DATA_AVAILABLE);

            try {
                fingerprintField = FingerPrintTask.class.getDeclaredField("fingerprint");
                fingerprintField.setAccessible(true);
            } catch (NoSuchFieldException | SecurityException e) {
                throw new RuntimeException(e);
            }
        }

        public void reset() {
            originalTicket = null;
        }

        private TicketSession createTicketSession() {
            byte[] masterSecret = new byte[48];
            byte[] ticket =
                    new byte
                            [params.prefixSize
                                    + params.contentLength
                                    + params.initialPaddingSize
                                    + params.suffixSize];
            byte[] padding = params.paddingType.create(params.initialPaddingSize);
            for (int i = 0; i < params.initialPaddingSize; i++) {
                ticket[params.prefixSize + params.contentLength + i] = padding[i];
            }
            return new TicketSession(masterSecret, ticket);
        }

        @Override
        public void bulkExecuteStateTasks(Iterable<State> stateList) {
            assertNull(originalTicket);
            // first connection, wants to get a ticket
            Iterator<State> iterator = stateList.iterator();
            State state = iterator.next();
            assertFalse(
                    iterator.hasNext(), "Expected first connection to only have a single state");

            TlsContext context = state.getTlsContext();
            context.setSelectedProtocolVersion(ProtocolVersion.TLS12);

            var session = createTicketSession();
            originalTicket = session.getTicket();
            context.setSessionList(Arrays.asList(session));

            WorkflowTrace trace = state.getWorkflowTrace();
            ReceiveTillAction receive = (ReceiveTillAction) trace.getLastReceivingAction();
            Mockito.spy(receive);
            Mockito.doReturn(Arrays.asList(new FinishedMessage(), new NewSessionTicketMessage()))
                    .when(receive)
                    .getReceivedMessages();
        }

        @Override
        public List<ITask> bulkExecuteTasks(Iterable<TlsTask> taskList) {
            for (TlsTask _task : taskList) {
                FingerPrintTask task = (FingerPrintTask) _task;
                ResponseFingerprint fingerprint = handleState(task.getState());
                try {
                    fingerprintField.set(task, fingerprint);
                } catch (SecurityException | IllegalArgumentException | IllegalAccessException e) {
                    throw new RuntimeException(e);
                }
            }
            // return value is not used
            return null;
        }

        protected ResponseFingerprint handleState(State state) {
            byte[] ticket = state.getConfig().getTlsSessionTicket();
            byte[] decryptedPaddingBlock = new byte[params.blockSize];
            // decOffset points to first byte of last block (hence subtract suffix [skip suffix] and
            // blockSize [point to start])
            int decOffset = ticket.length - params.suffixSize - params.blockSize;
            for (int i = 0; i < params.blockSize; i++) {
                int paddingPosition = decOffset + i;
                // "decrypt" by XORing previous ciphertext block (IV) and dec(current one)
                // NB: we do not have any actual encryption, hence dec=id is omitted
                decryptedPaddingBlock[i] =
                        (byte)
                                (ticket[paddingPosition]
                                        ^ ticket[paddingPosition - params.blockSize]);
            }

            int paddingLength =
                    params.paddingType.getPaddingLength(decryptedPaddingBlock, params.blockSize);
            boolean isOriginalTicket = Arrays.equals(ticket, originalTicket);
            return respond(isOriginalTicket, paddingLength);
        }

        public abstract ResponseFingerprint respond(boolean isOriginalTicket, int paddingLength);
    }

    private static class NoOracleExecutor extends OracleExecutorBase {

        public NoOracleExecutor(OracleParameters parameters) {
            super(parameters);
        }

        @Override
        public void reset() {
            super.reset();
        }

        @Override
        public ResponseFingerprint respond(boolean isOriginalTicket, int paddingLength) {
            if (isOriginalTicket) {
                assert paddingLength > 0;
                return fingerprintUseTicket;
            } else {
                return fingerprintAbortConnection;
            }
        }
    }

    private static class OracleExecutor extends OracleExecutorBase {
        public OracleExecutor(OracleParameters parameters) {
            super(parameters);
        }

        @Override
        public ResponseFingerprint respond(boolean isOriginalTicket, int paddingLength) {
            if (paddingLength <= 0) {
                return fingerprintAbortConnection;
            } else if (isOriginalTicket) {
                return fingerprintUseTicket;
            } else {
                return fingerprintIgnoreOrNoTicket;
            }
        }
    }

    private static class DummyConfigSelector extends ConfigSelector {
        public DummyConfigSelector(
                ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
            super(scannerConfig, parallelExecutor);
        }

        @Override
        public Config getBaseConfig() {
            return new Config();
        }
    }
}
