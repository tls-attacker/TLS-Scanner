/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.DigestAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.VersionDependentResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.VersionDependentSummarizableResult;
import de.rub.nds.tlsscanner.serverscanner.probe.result.VersionDependentTestResults;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketBaseProbe;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketUtil;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.ticket.Ticket;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;
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

public class SessionTicketProbe extends SessionTicketBaseProbe {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final int TICKETS_TO_GATHER = 10;

    // results
    private VersionDependentTestResults issuesTickets = new VersionDependentTestResults();
    private VersionDependentTestResults resumesTickets = new VersionDependentTestResults();
    private VersionDependentSummarizableResult<VersionDependentTestResults> allowsVersionChange =
            new VersionDependentSummarizableResult<>();
    private VersionDependentTestResults allowsCipherSuiteChange = new VersionDependentTestResults();
    private VersionDependentTestResults allowsReplayingTickets = new VersionDependentTestResults();
    private VersionDependentTestResults supportsEarlyData = new VersionDependentTestResults();
    private VersionDependentTestResults vulnerableToEarlyDataReplay =
            new VersionDependentTestResults();
    private VersionDependentResult<List<Ticket>> observedTickets = new VersionDependentResult<>();

    public SessionTicketProbe(ConfigSelector configSelector, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, configSelector, TlsProbeType.SESSION_TICKET);
        register(TlsAnalyzedProperty.ISSUES_TICKET);
        register(TlsAnalyzedProperty.RESUMES_WITH_TICKET);
        register(TlsAnalyzedProperty.ALLOW_CIPHERSUITE_CHANGE_TICKET);
        register(TlsAnalyzedProperty.ALLOW_VERSION_CHANGE_TICKET);
        register(TlsAnalyzedProperty.REPLAY_VULNERABLE_TICKET);
        register(TlsAnalyzedProperty.SUPPORTS_EARLY_DATA_TICKET);
        register(TlsAnalyzedProperty.REPLAY_VULNERABLE_EARLY_DATA_TICKET);
    }

    @Override
    public void executeTest() {
        for (ProtocolVersion version : versionsToTest) {
            try {
                checkIssuesTickets(version);
                checkIssuesTicketsConsistently(version);

                checkResumesWithTicket(version);
                checkVersionChange(version);
                checkAllowsCiphersuiteChange(version);

                checkReplayAttack(version);

                if (version.isTLS13()) {
                    check0RTT(version);
                    // TODO check replay attack for 0-RTT data
                }

            } catch (Exception E) {
                LOGGER.warn("Could not scan SessionTickets for version {}", version, E);
                if (E.getCause() instanceof InterruptedException) {
                    LOGGER.error("Timeout on {}", getProbeName());
                    throw E;
                }
            }
        }
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.setObservedTickets(observedTickets);
        put(TlsAnalyzedProperty.ISSUES_TICKET, issuesTickets);
        put(TlsAnalyzedProperty.RESUMES_WITH_TICKET, resumesTickets);
        put(TlsAnalyzedProperty.ALLOW_CIPHERSUITE_CHANGE_TICKET, allowsCipherSuiteChange);
        put(TlsAnalyzedProperty.ALLOW_VERSION_CHANGE_TICKET, allowsVersionChange);
        put(TlsAnalyzedProperty.REPLAY_VULNERABLE_TICKET, allowsReplayingTickets);
        put(TlsAnalyzedProperty.SUPPORTS_EARLY_DATA_TICKET, supportsEarlyData);
        put(TlsAnalyzedProperty.REPLAY_VULNERABLE_EARLY_DATA_TICKET, vulnerableToEarlyDataReplay);
    }

    private void checkIssuesTickets(ProtocolVersion version) {
        // check whether server issues one ticket
        State firstConnection = prepareInitialHandshake(version);
        executeState(firstConnection);

        boolean issuedTicket = initialHandshakeSuccessful(firstConnection);
        issuesTickets.putResult(version, issuedTicket);
        if (!issuedTicket) {
            return;
        }

        List<Ticket> tickets =
                new ArrayList<>(SessionTicketUtil.getSessionTickets(firstConnection));
        observedTickets.putResult(version, tickets);
    }

    private void checkIssuesTicketsConsistently(ProtocolVersion version) {
        if (issuesTickets.getResult(version) != TestResults.TRUE) {
            return;
        }

        List<State> statesToExecute = new LinkedList<>();
        for (int i = 0; i < TICKETS_TO_GATHER - 1; i++) {
            statesToExecute.add(prepareInitialHandshake(version));
        }
        executeState(statesToExecute);
        for (State state : statesToExecute) {
            if (!initialHandshakeSuccessful(state)) {
                this.issuesTickets.putResult(version, TestResults.PARTIALLY);
            } else {
                observedTickets
                        .getResult(version)
                        .addAll(SessionTicketUtil.getSessionTickets(state));
            }
        }
    }

    private void checkResumesWithTicket(ProtocolVersion version) {
        if (issuesTickets.getResult(version) != TestResults.TRUE) {
            resumesTickets.putResult(version, TestResults.COULD_NOT_TEST);
            return;
        }

        State initialState = prepareInitialHandshake(version);
        executeState(initialState);
        if (!initialHandshakeSuccessful(initialState)) {
            LOGGER.warn(
                    "Could not get a ticket to resume; even though tickets were issued earlier");
            resumesTickets.putResult(version, TestResults.ERROR_DURING_TEST);
            return;
        }
        State resumptionState =
                prepareResumptionHandshake(
                        version, SessionTicketUtil.getSessionTickets(initialState).get(0), false);
        executeState(resumptionState);
        boolean acceptedTicket = resumptionHandshakeSuccessful(resumptionState, false);
        resumesTickets.putResult(version, acceptedTicket);
    }

    private void check0RTT(ProtocolVersion version) {
        if (issuesTickets.getResult(version) != TestResults.TRUE) {
            supportsEarlyData.putResult(version, TestResults.COULD_NOT_TEST);
            return;
        }

        State initialState = prepareInitialHandshake(version);
        executeState(initialState);
        if (!initialHandshakeSuccessful(initialState)) {
            LOGGER.warn(
                    "Could not get a ticket to resume; even though tickets were issued earlier");
            supportsEarlyData.putResult(version, TestResults.ERROR_DURING_TEST);
            return;
        }
        State resumptionState =
                prepareResumptionHandshake(
                        version, SessionTicketUtil.getSessionTickets(initialState).get(0), true);

        // TODO figure out how to properly prepare the state/context/config
        resumptionState.replaceContext(initialState.getContext());

        executeState(resumptionState);
        boolean accepted0RTT = resumptionHandshakeSuccessful(resumptionState, true);
        supportsEarlyData.putResult(version, accepted0RTT);
    }

    private List<State> performInitialConnections(Integer number, ProtocolVersion version) {
        List<State> initialConnections = new ArrayList<>(number);
        for (int i = 0; i < number; i++) {
            State state = prepareInitialHandshake(version);
            initialConnections.add(state);
        }
        executeState(initialConnections);
        return initialConnections;
    }

    private Map<ProtocolVersion, State> performResumptionConnections(
            List<State> initialConnections, Iterable<ProtocolVersion> versions) {
        Map<ProtocolVersion, State> resumedConnections = new EnumMap<>(ProtocolVersion.class);
        for (ProtocolVersion target : versions) {
            State initialState = initialConnections.remove(0);
            if (!initialHandshakeSuccessful(initialState)) {
                LOGGER.warn("Initial Handshake failed; Could not test downgrade to {}", target);
                continue;
            }
            Ticket ticket = SessionTicketUtil.getSessionTickets(initialState).get(0);
            State state = prepareResumptionHandshake(target, ticket, false);
            resumedConnections.put(target, state);
        }

        executeState(resumedConnections.values());
        return resumedConnections;
    }

    private void checkVersionChange(ProtocolVersion fromVersion) {
        if (issuesTickets.getResult(fromVersion) != TestResults.TRUE) {
            allowsVersionChange.putResult(
                    fromVersion, new VersionDependentTestResults(TestResults.COULD_NOT_TEST));
            return;
        }
        VersionDependentTestResults result = new VersionDependentTestResults();
        allowsVersionChange.putResult(fromVersion, result);

        Set<ProtocolVersion> targetVersions = new HashSet<>();
        targetVersions.add(ProtocolVersion.TLS10);
        targetVersions.add(ProtocolVersion.TLS11);
        targetVersions.add(ProtocolVersion.TLS12);
        targetVersions.add(ProtocolVersion.TLS13);
        targetVersions.remove(fromVersion);
        targetVersions =
                targetVersions.stream()
                        .filter(version -> versionsToTest.contains(version))
                        .collect(Collectors.toSet());

        List<State> initialConnections =
                performInitialConnections(targetVersions.size(), fromVersion);

        Map<ProtocolVersion, State> resumedConnections =
                performResumptionConnections(initialConnections, targetVersions);

        for (ProtocolVersion target : targetVersions) {
            if (!resumedConnections.containsKey(target)) {
                result.putResult(target, TestResults.ERROR_DURING_TEST);
            } else {
                State state = resumedConnections.get(target);
                boolean boolResult = resumptionHandshakeSuccessful(state, false);
                result.putResult(target, boolResult);
            }
        }
    }

    /**
     * Find cipher suites that have the same digest algorithm
     *
     * @param protocolVersion version for which to get the digest algorithm
     * @return List of ciphersuites supported by the server which have at least one other cipher
     *     suite supported by the server that shares the digest algorithm
     */
    private List<CipherSuite> findCiphersuitesForCiphersuiteChange(
            ProtocolVersion protocolVersion) {
        Map<DigestAlgorithm, List<CipherSuite>> supportedSuitesByDigest =
                new EnumMap<>(DigestAlgorithm.class);
        for (CipherSuite suite : supportedSuites) {
            if (!suite.isSupportedInProtocol(protocolVersion)) {
                continue;
            }
            DigestAlgorithm digestAlgorithm =
                    AlgorithmResolver.getDigestAlgorithm(protocolVersion, suite);
            if (!supportedSuitesByDigest.containsKey(digestAlgorithm)) {
                supportedSuitesByDigest.put(digestAlgorithm, new ArrayList<>());
            }
            supportedSuitesByDigest.get(digestAlgorithm).add(suite);
        }

        List<CipherSuite> ret = new ArrayList<>();
        for (Entry<DigestAlgorithm, List<CipherSuite>> entry : supportedSuitesByDigest.entrySet()) {
            if (entry.getValue().size() >= 2) {
                ret.addAll(entry.getValue());
            }
        }
        return ret;
    }

    private void checkAllowsCiphersuiteChange(ProtocolVersion version) {
        if (issuesTickets.getResult(version) != TestResults.TRUE) {
            allowsCipherSuiteChange.putResult(version, TestResults.COULD_NOT_TEST);
            return;
        }

        State initialState = prepareInitialHandshake(version);
        if (version.isTLS13()) {
            List<CipherSuite> suitesToTest =
                    findCiphersuitesForCiphersuiteChange(ProtocolVersion.TLS13);
            initialState.getConfig().setDefaultClientSupportedCipherSuites(suitesToTest);
        }
        executeState(initialState);
        if (!initialHandshakeSuccessful(initialState)) {
            LOGGER.warn("Initial Handshake failed; Could not test CipherSuite change");
            allowsCipherSuiteChange.putResult(version, TestResults.ERROR_DURING_TEST);
            return;
        }

        CipherSuite initialSuite = initialState.getTlsContext().getSelectedCipherSuite();
        Ticket ticket = SessionTicketUtil.getSessionTickets(initialState).get(0);

        State resumptionState = prepareResumptionHandshake(version, ticket, false);
        resumptionState.getConfig().getDefaultClientSupportedCipherSuites().remove(initialSuite);
        if (version.isTLS13()) {
            // in TLS 1.3 resumption with different cipher suites only works with if MAC algorithm
            // of session cipher is used since the binder calculation uses the MAC algorithm
            DigestAlgorithm initialDigestAlgorithm =
                    AlgorithmResolver.getDigestAlgorithm(version, initialSuite);
            resumptionState
                    .getConfig()
                    .getDefaultClientSupportedCipherSuites()
                    .removeIf(
                            suite ->
                                    AlgorithmResolver.getDigestAlgorithm(version, suite)
                                            != initialDigestAlgorithm);
        }
        executeState(resumptionState);

        boolean allowsChange =
                resumptionHandshakeSuccessful(resumptionState, false)
                        && resumptionState.getTlsContext().getSelectedCipherSuite() != initialSuite;
        allowsCipherSuiteChange.putResult(version, allowsChange);
    }

    private void checkReplayAttack(ProtocolVersion version) {
        if (resumesTickets.getResult(version) != TestResults.TRUE) {
            allowsReplayingTickets.putResult(version, TestResults.COULD_NOT_TEST);
            return;
        }

        State initialState = prepareInitialHandshake(version);
        executeState(initialState);
        if (!initialHandshakeSuccessful(initialState)) {
            LOGGER.warn(
                    "Could not get a ticket to resume; even though tickets were issued earlier");
            allowsReplayingTickets.putResult(version, TestResults.ERROR_DURING_TEST);
            return;
        }

        State resumptionState =
                prepareResumptionHandshake(
                        version, SessionTicketUtil.getSessionTickets(initialState).get(0), false);
        executeState(resumptionState);
        if (!resumptionHandshakeSuccessful(resumptionState, false)) {
            LOGGER.warn("Could not resume ticket; even though tickets were resumed earlier");
            allowsReplayingTickets.putResult(version, TestResults.ERROR_DURING_TEST);
            return;
        }

        State replayState =
                prepareResumptionHandshake(
                        version, SessionTicketUtil.getSessionTickets(initialState).get(0), false);
        executeState(replayState);
        boolean acceptedTicket = resumptionHandshakeSuccessful(replayState, false);
        allowsReplayingTickets.putResult(version, acceptedTicket);
    }
}
