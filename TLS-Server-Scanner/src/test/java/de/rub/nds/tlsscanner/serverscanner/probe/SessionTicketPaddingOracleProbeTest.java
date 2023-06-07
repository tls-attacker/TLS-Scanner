/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import de.rub.nds.tlsattacker.attacks.task.FingerPrintTask;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.state.session.TicketSession;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.task.ITask;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsattacker.transport.socket.SocketState;
import de.rub.nds.tlsattacker.util.tests.SlowTests;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.SessionTicketProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket.TicketPaddingOracleResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket.TicketResult;

public class SessionTicketPaddingOracleProbeTest {

    private List<OracleParameters> PARAMETERS;

    public SessionTicketPaddingOracleProbeTest() {

    }

    @Before
    public void setUp() {
        PARAMETERS = new ArrayList<>();
        // just two blocks
        PARAMETERS.add(new OracleParameters(16, 16, 16, 16, PaddingType.CONSTANT_START_AT_ONE));
        // just two blocks, no mac
        PARAMETERS.add(new OracleParameters(16, 16, 0, 16, PaddingType.CONSTANT_START_AT_ONE));
        // no mac, different padding lengths
        for (int i = 1; i <= 16; i++) {
            PARAMETERS.add(new OracleParameters(32 - i, i, 0, 16, PaddingType.CONSTANT_START_AT_ONE));
        }
        // no mac, different padding lengths, not aligned with blocks
        for (int i = 1; i <= 16; i++) {
            PARAMETERS.add(new OracleParameters(35 - i, i, 0, 16, PaddingType.CONSTANT_START_AT_ONE));
        }

        // smaller blocksize
        PARAMETERS.add(new OracleParameters(8, 8, 20, 8, PaddingType.CONSTANT_START_AT_ONE));
        PARAMETERS.add(new OracleParameters(8 + 5, 3, 0, 8, PaddingType.CONSTANT_START_AT_ONE));
        PARAMETERS.add(new OracleParameters(8 + 7, 1, 0, 8, PaddingType.CONSTANT_START_AT_ONE));

        // different mac sizes, not aligned with blocks, different padding
        for (int macSize : new int[] { 0, 16, 20, 28, 32, 48, 64 }) {
            PARAMETERS.add(new OracleParameters(42, 6, macSize, 16, PaddingType.CONSTANT_START_AT_ZERO));
        }
        // different padding
        PARAMETERS.add(new OracleParameters(42, 3, 0, 16, PaddingType.COUNTING_UP_START_AT_ZERO));
    }

    @Test
    @Category(SlowTests.class)
    public void testNoOracle() {
        for (OracleParameters parameters : PARAMETERS) {
            NoOracleExecutor executor = new NoOracleExecutor(parameters);
            var result = runProbe(executor);
            assertEquals(parameters + " resulted in wrong result", TestResult.FALSE, result.getOverallResult());
        }
    }

    @Test
    @Category(SlowTests.class)
    public void testOracle() {
        for (OracleParameters parameters : PARAMETERS) {
            var result = runProbe(new OracleExecutor(parameters));
            assertEquals(parameters + " resulted in wrong result", TestResult.TRUE, result.getOverallResult());
        }
    }

    @Test
    public void testNoOracleFast() {
        OracleParameters parameters = PARAMETERS.get(0);
        var result = runProbe(new NoOracleExecutor(parameters));
        assertEquals(parameters + " resulted in wrong result", TestResult.FALSE, result.getOverallResult());
    }

    @Test
    public void testOracleFast() {
        OracleParameters parameters = PARAMETERS.get(0);
        var result = runProbe(new OracleExecutor(parameters));
        assertEquals(parameters + " resulted in wrong result", TestResult.TRUE, result.getOverallResult());
    }

    public TicketPaddingOracleResult runProbe(OracleExecutorBase executor) {
        SiteReport report = new SiteReport("foohost", -1);
        report.setVersions(Arrays.asList(ProtocolVersion.TLS12));
        report.setCipherSuites(new HashSet<>(Arrays.asList(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)));
        SessionTicketProbeResult sessionResult = new SessionTicketProbeResult();
        TicketResult ticketResult = TicketResult.create(ProtocolVersion.TLS12);
        ticketResult.setIssuesTickets(TestResult.TRUE);
        sessionResult.putResult(ticketResult);
        report.setSessionTicketProbeResult(sessionResult);
        executor.reset();
        ScannerConfig config = new ScannerConfig(new GeneralDelegate());
        config.getClientDelegate().setHost("foohost");
        SessionTicketPaddingOracleProbe probe = new SessionTicketPaddingOracleProbe(config, executor);

        probe.adjustConfig(report);
        probe.executeAndMerge(report);
        return report.getSessionTicketPaddingOracleResult().getResult(ProtocolVersion.TLS12);
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
        public final int prefixSize;
        public final int initialPaddingSize;
        public final int suffixSize;
        public final int blockSize;
        public final PaddingType paddingType;

        public OracleParameters(int prefixSize, int initialPaddingSize, int suffixSize, int blockSize,
            PaddingType paddingType) {
            if (initialPaddingSize > blockSize) {
                throw new IllegalArgumentException("padding must be at most one block");
            }
            if (initialPaddingSize <= 0) {
                throw new IllegalArgumentException("padding must be at least 1");
            }
            if (prefixSize + initialPaddingSize < 2 * blockSize) {
                throw new IllegalArgumentException("prefix+padding must be at least two blocks");
            }
            this.prefixSize = prefixSize;
            this.initialPaddingSize = initialPaddingSize;
            this.suffixSize = suffixSize;
            this.blockSize = blockSize;
            this.paddingType = paddingType;
        }

        @Override
        public String toString() {
            return String.format("{prefixSize=%d, initialPaddingSize=%d, suffixSize=%d, blockSize=%d, paddingType=%s}",
                prefixSize, initialPaddingSize, suffixSize, blockSize, paddingType);
        }

    }

    private static abstract class OracleExecutorBase extends ParallelExecutor {
        protected final ResponseFingerprint fingerprintAbortConnection, fingerprintIgnoreOrNoTicket,
            fingerprintUseTicket;

        public final int prefixSize;
        public final byte initialPaddingSize;
        public final int suffixSize;
        public final int blockSize;
        public final PaddingType paddingType;

        public byte[] originalTicket = null;
        private final Field fingerprintField;

        public OracleExecutorBase(int prefixSize, int initialPaddingSize, int suffixSize, int blockSize,
            PaddingType paddingType) {
            super(1, 0);
            if (initialPaddingSize > blockSize) {
                throw new IllegalArgumentException("padding must be at most one block");
            }
            if (initialPaddingSize <= 0) {
                throw new IllegalArgumentException("padding must be at least 1");
            }
            if (prefixSize + initialPaddingSize < 2 * blockSize) {
                throw new IllegalArgumentException("prefix+padding must be at least two blocks");
            }
            this.prefixSize = prefixSize;
            this.initialPaddingSize = (byte) initialPaddingSize;
            this.suffixSize = suffixSize;
            this.blockSize = blockSize;
            this.paddingType = paddingType;

            List<AbstractRecord> recordList = new ArrayList<>();
            fingerprintAbortConnection = new ResponseFingerprint(Arrays.asList(), recordList, SocketState.IO_EXCEPTION);
            fingerprintIgnoreOrNoTicket = new ResponseFingerprint(
                Arrays.asList(new ServerHelloMessage(), new CertificateMessage(), new ServerHelloDoneMessage()),
                recordList, SocketState.DATA_AVAILABLE);
            fingerprintUseTicket =
                new ResponseFingerprint(Arrays.asList(new ServerHelloMessage(), new ServerHelloDoneMessage()),
                    recordList, SocketState.DATA_AVAILABLE);

            try {
                fingerprintField = FingerPrintTask.class.getDeclaredField("fingerprint");
                fingerprintField.setAccessible(true);
            } catch (NoSuchFieldException | SecurityException e) {
                throw new RuntimeException(e);
            }
        }

        public OracleExecutorBase(OracleParameters parameters) {
            this(parameters.prefixSize, parameters.initialPaddingSize, parameters.suffixSize, parameters.blockSize,
                parameters.paddingType);
        }

        public void reset() {
            originalTicket = null;
        }

        private TicketSession createTicketSession() {
            byte[] masterSecret = new byte[48];
            byte[] ticket = new byte[prefixSize + initialPaddingSize + suffixSize];
            byte[] padding = paddingType.create(initialPaddingSize);
            for (int i = 0; i < initialPaddingSize; i++) {
                ticket[prefixSize + i] = padding[i];
            }
            return new TicketSession(masterSecret, ticket);
        }

        @Override
        public void bulkExecuteStateTasks(Iterable<State> stateList) {
            assertNull(originalTicket);
            // first connection, wants to get a ticket
            Iterator<State> iterator = stateList.iterator();
            State state = iterator.next();
            assertFalse("Expected first connection to only have a single state", iterator.hasNext());

            TlsContext context = state.getTlsContext();
            context.setSelectedProtocolVersion(ProtocolVersion.TLS12);

            var session = createTicketSession();
            originalTicket = session.getTicket();
            context.setSessionList(Arrays.asList(session));

            WorkflowTrace trace = state.getWorkflowTrace();
            ReceiveAction receive = (ReceiveAction) trace.getLastReceivingAction();
            receive.setMessages(Arrays.asList(new FinishedMessage(), new NewSessionTicketMessage()));
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
            byte[] decryptedPaddingBlock = new byte[blockSize];
            // "decrypt"
            int decOffset = ticket.length - suffixSize - blockSize;
            for (int i = 0; i < blockSize; i++) {
                int paddingPosition = decOffset + i;
                decryptedPaddingBlock[i] = (byte) (ticket[paddingPosition] ^ ticket[paddingPosition - blockSize]);
            }

            int paddingLength = paddingType.getPaddingLength(decryptedPaddingBlock, blockSize);
            boolean isOriginalTicket = paddingLength > 0 && Arrays.equals(ticket, originalTicket);
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
}
