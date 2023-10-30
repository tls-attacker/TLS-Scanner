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
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.task.FingerPrintTask;
import de.rub.nds.tlsscanner.core.task.FingerprintTaskVectorPair;
import de.rub.nds.tlsscanner.core.vector.VectorResponse;
import de.rub.nds.tlsscanner.core.vector.response.ResponseFingerprint;
import de.rub.nds.tlsscanner.serverscanner.probe.result.VersionDependentSummarizableResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.TicketManipulationResult;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketBaseProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketUtil;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.ModifiedTicket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.NoTicket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketBitFlipVector;
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

/**
 * Test to check how the server behaves if the ticket is modified. A secure server would reject all
 * tickets which are modified due to an invalidated MAC.
 *
 * <p>This test retrieves a ticket, then induces bitflips and tries to resume with this ticket. The
 * responses of the server are fingerprinted and evaluated.
 */
public class SessionTicketManipulationProbe extends SessionTicketBaseProbe {
    private static final Logger LOGGER = LogManager.getLogger();

    VersionDependentSummarizableResult<TicketManipulationResult> overallResult;

    public SessionTicketManipulationProbe(
            ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, configSelector, TlsProbeType.SESSION_TICKET_MANIPULATION);
        register(TlsAnalyzedProperty.NO_MAC_CHECK_TICKET);
    }

    @Override
    public void executeTest() {
        overallResult = new VersionDependentSummarizableResult<>();
        for (ProtocolVersion version : versionsToTest) {
            try {
                overallResult.putResult(version, checkManipulation(version));
            } catch (Exception E) {
                LOGGER.error("Could not scan SessionTicketManipulation for version {}", version, E);
                overallResult.putResult(
                        version, new TicketManipulationResult(TestResults.ERROR_DURING_TEST));
                if (E.getCause() instanceof InterruptedException) {
                    LOGGER.error("Timeout on {}", getProbeName());
                    throw E;
                }
            }
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        put(TlsAnalyzedProperty.NO_MAC_CHECK_TICKET, overallResult);
    }

    /**
     * Utility function to perform a handshake without a ticket.
     *
     * @param version Version to perform the handshake in
     * @return The FingerPrint of the handshake.
     */
    private ResponseFingerprint fingerprintInitialHandshake(ProtocolVersion version) {
        FingerPrintTask fingerPrintTask =
                prepareResumptionFingerprintTask(version, new NoTicket(), false);
        patchTraceMightFailAfterMessage(
                fingerPrintTask.getState().getWorkflowTrace(), HandshakeMessageType.SERVER_HELLO);
        getParallelExecutor().bulkExecuteTasks(fingerPrintTask);
        return fingerPrintTask.getFingerprint();
    }

    /**
     * Utility function to change preshared secrets in config, such that they diverge from the
     * secrets stored in the ticket
     *
     * @param version Version for which the secrets should be changed
     * @param config config containing the correct secrets+tickets
     */
    private void changeSecrets(ProtocolVersion version, Config config) {
        if (version.isTLS13()) {
            byte[] psk = config.getPsk();
            psk[0] ^= 0xff;
            config.setPsk(psk);
            for (PskSet pskSet : config.getDefaultPskSets()) {
                psk = pskSet.getPreSharedKey();
                psk[0] ^= 0xff;
                pskSet.setPreSharedKey(psk);
            }
        } else {
            byte[] masterSecret = config.getDefaultMasterSecret();
            masterSecret[0] ^= 0xff;
            config.setDefaultMasterSecret(masterSecret);
        }
    }

    /**
     * Utility function to perform a handshake and a resumption. It can also perform the resumption
     * without knowing the correct secrets. This is to be used to create fingerprints for different
     * scenarios.
     *
     * @param version Version to perform the handshake (+ resumption) in
     * @param resume Whether to resume the session or not. This influences which state is returned.
     * @param changeSecrets When resuming the session: Whether to change the local secrets before
     *     resuming or not. If the secrets are changed, the server's and our secrets do not match.
     *     Can be useful for fingerprinting.
     * @return The FingerPrint of the resumption handshake or null if no initial ticket was issued.
     */
    private ResponseFingerprint fingerprintResumptionHandshake(
            ProtocolVersion version, boolean changeSecrets) {
        State initialHandshake = prepareInitialHandshake(version);
        executeState(initialHandshake);
        if (!initialHandshakeSuccessful(initialHandshake)) {
            return null;
        }

        Ticket ticket = SessionTicketUtil.getSessionTickets(initialHandshake).get(0);
        FingerPrintTask fingerPrintTask = prepareResumptionFingerprintTask(version, ticket, false);

        if (changeSecrets) {
            changeSecrets(version, fingerPrintTask.getState().getConfig());
            // patch trace to ignore errors after ccs
            patchTraceMightFailAfterMessage(
                    fingerPrintTask.getState().getWorkflowTrace(),
                    ProtocolMessageType.CHANGE_CIPHER_SPEC);
        }

        getParallelExecutor().bulkExecuteTasks(fingerPrintTask);
        return fingerPrintTask.getFingerprint();
    }

    private TicketManipulationResult checkManipulation(ProtocolVersion version) {
        // perform 4(+2) handshakes before running test
        // 1. Normal handshake: Get a ticket
        // 2. Without ticket -> fingerprint (same as if ticket was ignored)
        // 3. (+1 /wo ticket) With ticket -> fingerprint
        // 4. (+1 /wo ticket) With ticket, but different secret -> fingerprint
        // For 3/4 we get fresh tickets, such that a replay protection does not mark our initial
        // ticket as used

        State ticketState = prepareInitialHandshake(version);
        executeState(ticketState);
        if (!initialHandshakeSuccessful(ticketState)) {
            LOGGER.warn("Initial Handshake failed {}", version);
            return new TicketManipulationResult(TestResults.ERROR_DURING_TEST);
        }
        Ticket ticketToModify = SessionTicketUtil.getSessionTickets(ticketState).get(0);

        ResponseFingerprint rejectFingerprint = fingerprintInitialHandshake(version);
        ResponseFingerprint acceptFingerprint = fingerprintResumptionHandshake(version, false);
        ResponseFingerprint acceptDifferentSecretFingerprint =
                fingerprintResumptionHandshake(version, true);

        if (ticketToModify == null
                || rejectFingerprint == null
                || acceptFingerprint == null
                || acceptDifferentSecretFingerprint == null) {
            LOGGER.warn("Initial Handshake for Fingerprinting failed {}", version);
            return new TicketManipulationResult(TestResults.ERROR_DURING_TEST);
        }

        List<FingerprintTaskVectorPair<TicketBitFlipVector>> taskList = new ArrayList<>();
        for (TicketBitFlipVector vector :
                createVectors(
                        ticketToModify.getTicketBytesOriginal().length * 8,
                        configSelector.getScannerConfig().getExecutorConfig().getScanDetail())) {
            ModifiedTicket ticket = vector.createTicket(ticketToModify);
            FingerPrintTask task =
                    prepareResumptionFingerprintTask(
                            version, ticket, false, HandshakeMessageType.SERVER_HELLO);
            taskList.add(new FingerprintTaskVectorPair<>(task, vector));
        }

        getParallelExecutor()
                .bulkExecuteTasks(
                        taskList.stream()
                                .map(FingerprintTaskVectorPair::getFingerPrintTask)
                                .collect(Collectors.toList()));

        boolean acceptedModifiedTicket = false;
        Map<Integer, VectorResponse> responses = new HashMap<>();
        // extract fingerprints and compute overall result (acceptedModifiedTicket)
        for (FingerprintTaskVectorPair<TicketBitFlipVector> task : taskList) {
            TicketBitFlipVector vector = task.getVector();
            VectorResponse response = task.toVectorResponse();
            State resumedState = task.getFingerPrintTask().getState();
            ResponseFingerprint fingerprint = response.getFingerprint();
            responses.put(vector.position, response);

            // once true, keep it true
            // otherwise check fingerprint or whether resumption was successful
            acceptedModifiedTicket =
                    acceptedModifiedTicket
                            || fingerprint.equals(acceptFingerprint)
                            || resumptionHandshakeSuccessful(resumedState, false)
                            || fingerprint.equals(acceptDifferentSecretFingerprint);
        }
        return new TicketManipulationResult(
                TestResults.of(acceptedModifiedTicket),
                responses,
                acceptFingerprint,
                acceptDifferentSecretFingerprint,
                rejectFingerprint);
    }

    private List<TicketBitFlipVector> createVectors(
            int ticketLengthInBits, ScannerDetail scannerDetail) {
        Set<Integer> positions = getBitflipPositions(ticketLengthInBits, scannerDetail);
        return positions.stream().map(TicketBitFlipVector::new).collect(Collectors.toList());
    }

    private Set<Integer> getBitflipPositions(int ticketLengthInBits, ScannerDetail scannerDetail) {
        Set<Integer> ret = new HashSet<>();
        int stepsize = 8; // first bit of each byte
        if (scannerDetail.getLevelValue() >= ScannerDetail.ALL.getLevelValue()) {
            // all bits
            stepsize = 1;
        }
        for (int i = 0; i < ticketLengthInBits; i += stepsize) {
            ret.add(i);
        }
        return ret;
    }

    @Override
    public Requirement<ServerReport> getRequirements() {
        return super.getRequirements().and(REQ_SUPPORTS_RESUMPTION);
    }
}
