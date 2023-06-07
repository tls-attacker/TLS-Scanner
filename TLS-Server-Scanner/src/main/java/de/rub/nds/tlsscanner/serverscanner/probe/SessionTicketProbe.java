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
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketBaseProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketUtil;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.SessionTicketProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket.TicketResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket.TicketResultTls13;

public class SessionTicketProbe extends SessionTicketBaseProbe {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final int TICKETS_TO_GATHER = 10;

    public SessionTicketProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.SESSION_TICKET, scannerConfig);
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new SessionTicketProbeResult();
    }

    @Override
    public SessionTicketProbeResult executeTest() {
        // TODO (minor) it might make sense to look at a stat extractor to extract the tickets

        SessionTicketProbeResult overallResult = new SessionTicketProbeResult();
        for (ProtocolVersion version : versionsToTest) {
            TicketResult result = TicketResult.create(version);
            assert result.getProtocolVersion() == version
                : "Internal data corruption; result version is not as expected";

            try {
                checkIssuesTickets(result);

                checkResumesWithTicket(result);
                checkVersionChange(result);
                checkAllowsCiphersuiteChange(result);

                checkReplayAttack(result);

                // 1.3 only
                if (version.isTLS13()) {
                    TicketResultTls13 result13 = (TicketResultTls13) result;
                    check0RTT(result13);
                    // TODO check replay attack for 0-RTT data
                }

                overallResult.putResult(result);
            } catch (Exception E) {
                LOGGER.warn("Could not scan SessionTickets for version {}", version, E);
                overallResult.putResult(TicketResult.create(version, TestResult.ERROR_DURING_TEST));
                if (E.getCause() instanceof InterruptedException) {
                    LOGGER.error("Timeout on {}", getProbeName());
                    throw E;
                }
            }
        }
        return overallResult;
    }

    private void checkIssuesTickets(TicketResult resultToFill) {
        // check whether server issues one ticket
        State firstConnection = prepareInitialHandshake(resultToFill.getProtocolVersion());
        executeState(firstConnection);

        boolean issuesTickets = initialHandshakeSuccessful(firstConnection);
        resultToFill.setIssuesTickets(TestResult.of(issuesTickets));
        if (!issuesTickets) {
            return;
        }

        resultToFill.getTicketList().addAll(SessionTicketUtil.getSessionTickets(firstConnection));

        // gather more tickets
        List<State> statesToExecute = new LinkedList<>();
        for (int i = 0; i < TICKETS_TO_GATHER - 1; i++) {
            statesToExecute.add(prepareInitialHandshake(resultToFill.getProtocolVersion()));
        }
        executeState(statesToExecute);
        for (State state : statesToExecute) {
            if (!initialHandshakeSuccessful(state)) {
                resultToFill.setIssuesTickets(TestResult.PARTIALLY);
                return;
            }
            resultToFill.getTicketList().addAll(SessionTicketUtil.getSessionTickets(state));
        }
    }

    private void checkResumesWithTicket(TicketResult resultToFill) {
        if (resultToFill.getIssuesTickets() != TestResult.TRUE) {
            resultToFill.setResumesWithTicket(TestResult.COULD_NOT_TEST);
            return;
        }

        State initialState = prepareInitialHandshake(resultToFill.getProtocolVersion());
        executeState(initialState);
        if (!initialHandshakeSuccessful(initialState)) {
            LOGGER.warn("Could not get a ticket to resume; even though tickets were issued earlier");
            resultToFill.setResumesWithTicket(TestResult.ERROR_DURING_TEST);
            return;
        }
        State resumptionState = prepareResumptionHandshake(resultToFill.getProtocolVersion(),
            SessionTicketUtil.getSessionTickets(initialState).get(0), false);
        executeState(resumptionState);
        boolean acceptedTicket = resumptionHandshakeSuccessful(resumptionState, false);
        resultToFill.setResumesWithTicket(TestResult.of(acceptedTicket));
    }

    private void check0RTT(TicketResultTls13 resultToFill) {
        if (resultToFill.getIssuesTickets() != TestResult.TRUE) {
            resultToFill.setEarlyDataSupport(TestResult.COULD_NOT_TEST);
            return;
        }

        State initialState = prepareInitialHandshake(resultToFill.getProtocolVersion());
        executeState(initialState);
        if (!initialHandshakeSuccessful(initialState)) {
            LOGGER.warn("Could not get a ticket to resume; even though tickets were issued earlier");
            resultToFill.setEarlyDataSupport(TestResult.ERROR_DURING_TEST);
            return;
        }
        State resumptionState = prepareResumptionHandshake(resultToFill.getProtocolVersion(),
            SessionTicketUtil.getSessionTickets(initialState).get(0), true);

        // TODO figure out how to properly prepare the state/context/config
        resumptionState.replaceTlsContext(initialState.getTlsContext());

        executeState(resumptionState);
        boolean accepted0RTT = resumptionHandshakeSuccessful(resumptionState, true);
        resultToFill.setEarlyDataSupport(TestResult.of(accepted0RTT));
    }

    private void checkVersionChange(TicketResult resultToFill) {
        if (resultToFill.getIssuesTickets() != TestResult.TRUE) {
            // could not test
            return;
        }

        ProtocolVersion fromVersion = resultToFill.getProtocolVersion();
        Set<ProtocolVersion> targetVersions = new HashSet<>();
        targetVersions.add(ProtocolVersion.TLS10);
        targetVersions.add(ProtocolVersion.TLS11);
        targetVersions.add(ProtocolVersion.TLS12);
        targetVersions.add(ProtocolVersion.TLS13);
        targetVersions.remove(fromVersion);
        targetVersions =
            targetVersions.stream().filter(version -> versionsToTest.contains(version)).collect(Collectors.toSet());

        List<State> initialConnections = new ArrayList<>(targetVersions.size());
        // get tickets
        for (int i = 0; i < targetVersions.size(); i++) {
            State state = prepareInitialHandshake(fromVersion);
            initialConnections.add(state);
        }
        executeState(initialConnections);

        // resume tickets
        Map<ProtocolVersion, State> resumedConnections = new EnumMap<>(ProtocolVersion.class);
        for (ProtocolVersion target : targetVersions) {
            State initialState = initialConnections.remove(0);
            if (!initialHandshakeSuccessful(initialState)) {
                LOGGER.warn("Initial Handshake failed; Could not test downgrade from {} to {}", fromVersion, target);
                resultToFill.setVersionChangeResult(target, TestResult.ERROR_DURING_TEST);
                continue;
            }
            Ticket ticket = SessionTicketUtil.getSessionTickets(initialState).get(0);
            State state = prepareResumptionHandshake(target, ticket, false);
            resumedConnections.put(target, state);
        }

        executeState(resumedConnections.values());

        // analyze results
        for (Entry<ProtocolVersion, State> entry : resumedConnections.entrySet()) {
            boolean result = resumptionHandshakeSuccessful(entry.getValue(), false);
            resultToFill.setVersionChangeResult(entry.getKey(), TestResult.of(result));
        }
    }

    private void checkAllowsCiphersuiteChange(TicketResult resultToFill) {
        if (resultToFill.getIssuesTickets() != TestResult.TRUE) {
            resultToFill.setAllowsCiphersuiteChange(TestResult.COULD_NOT_TEST);
            return;
        }

        State initialState = prepareInitialHandshake(resultToFill.getProtocolVersion());
        executeState(initialState);
        if (!initialHandshakeSuccessful(initialState)) {
            LOGGER.warn("Initial Handshake failed; Could not test CipherSuite change");
            resultToFill.setAllowsCiphersuiteChange(TestResult.ERROR_DURING_TEST);
            return;
        }
        CipherSuite initialSuite = initialState.getTlsContext().getSelectedCipherSuite();
        Ticket ticket = SessionTicketUtil.getSessionTickets(initialState).get(0);

        State resumptionState = prepareResumptionHandshake(resultToFill.getProtocolVersion(), ticket, false);
        resumptionState.getConfig().getDefaultClientSupportedCipherSuites().remove(initialSuite);
        if (resultToFill.getProtocolVersion().isTLS13()) {
            // in TLS 1.3 resumption with different ciper suites only works with if MAC algorithm of session cipher is
            // used since the binder calculation uses the MAC algorithm
            DigestAlgorithm initialDigestAlgorithm =
                AlgorithmResolver.getDigestAlgorithm(resultToFill.getProtocolVersion(), initialSuite);
            resumptionState.getConfig().getDefaultClientSupportedCipherSuites()
                .removeIf(suite -> AlgorithmResolver.getDigestAlgorithm(resultToFill.getProtocolVersion(), suite)
                    != initialDigestAlgorithm);
        }
        executeState(resumptionState);

        boolean allowsChange = resumptionHandshakeSuccessful(resumptionState, false)
            && resumptionState.getTlsContext().getSelectedCipherSuite() != initialSuite;
        resultToFill.setAllowsCiphersuiteChange(TestResult.of(allowsChange));
    }

    private void checkReplayAttack(TicketResult resultToFill) {
        if (resultToFill.getResumesWithTicket() != TestResult.TRUE) {
            resultToFill.setReplayVulnerable(TestResult.COULD_NOT_TEST);
            return;
        }

        State initialState = prepareInitialHandshake(resultToFill.getProtocolVersion());
        executeState(initialState);
        if (!initialHandshakeSuccessful(initialState)) {
            LOGGER.warn("Could not get a ticket to resume; even though tickets were issued earlier");
            resultToFill.setReplayVulnerable(TestResult.ERROR_DURING_TEST);
            return;
        }

        State resumptionState = prepareResumptionHandshake(resultToFill.getProtocolVersion(),
            SessionTicketUtil.getSessionTickets(initialState).get(0), false);
        executeState(resumptionState);
        if (!resumptionHandshakeSuccessful(resumptionState, false)) {
            LOGGER.warn("Could not resume ticket; even though tickets were resumed earlier");
            resultToFill.setReplayVulnerable(TestResult.ERROR_DURING_TEST);
            return;
        }

        State replayState = prepareResumptionHandshake(resultToFill.getProtocolVersion(),
            SessionTicketUtil.getSessionTickets(initialState).get(0), false);
        executeState(replayState);
        boolean acceptedTicket = resumptionHandshakeSuccessful(replayState, false);
        resultToFill.setReplayVulnerable(TestResult.of(acceptedTicket));
    }
}
