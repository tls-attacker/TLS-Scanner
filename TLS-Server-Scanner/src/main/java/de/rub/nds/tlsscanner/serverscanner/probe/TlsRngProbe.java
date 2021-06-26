/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.*;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.stats.ComparableByteArray;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.TlsRngResult;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * A probe which samples random material from the target host using ServerHello randoms, SessionIDs and IVs.
 *
 * @author Dennis Ziebart - dziebart@mail.uni-paderborn.de
 */
public class TlsRngProbe extends TlsProbe {

    // Fixed Amount of required Handshakes
    private final int NUMBER_OF_HANDSHAKES = 500;

    // How much the time is allowed to deviate between two handshakes when
    // viewed using UNIX time prefix
    private final int UNIX_TIME_ALLOWED_DEVIATION = 500;
    // Amount of retries allowed when failing to receive ServerHello messages in
    // the Unix Time test
    private final int UNIX_TIME_CONNECTIONS = 5;
    // How many of the 3 ServerHello randoms should pass the Unix Time test at
    // minimum.
    private final int MINIMUM_MATCH_COUNTER = 2;

    private ProtocolVersion highestVersion;
    private boolean supportsExtendedRandom;
    private SiteReport latestReport;
    private LinkedList<ComparableByteArray> extractedIVList;
    private LinkedList<ComparableByteArray> extractedRandomList;
    private LinkedList<ComparableByteArray> extractedSessionIDList;

    private boolean usesUnixTime = false;

    public TlsRngProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RNG, config);
    }

    @Override
    public ProbeResult executeTest() {
        extractedIVList = new LinkedList<>();
        extractedRandomList = new LinkedList<>();
        extractedSessionIDList = new LinkedList<>();
        highestVersion = ProtocolVersion.TLS13;
        usesUnixTime = checkForUnixTime();

        collectData(NUMBER_OF_HANDSHAKES);

        return new TlsRngResult(extractedIVList, extractedRandomList, extractedSessionIDList, usesUnixTime);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) == TestResult.NOT_TESTED_YET
            || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) == TestResult.NOT_TESTED_YET
            || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) == TestResult.NOT_TESTED_YET
            || report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) == TestResult.NOT_TESTED_YET
            || report.getResult(AnalyzedProperty.SUPPORTS_RSA) == TestResult.NOT_TESTED_YET
            || report.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.NOT_TESTED_YET
            || report.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) == TestResult.NOT_TESTED_YET
            || report.getResult(AnalyzedProperty.GROUPS_DEPEND_ON_CIPHER) == TestResult.NOT_TESTED_YET) {
            return false;
        } else {
            return true;
        }
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new TlsRngResult(null, null, null, false);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        // We will conduct the rng extraction based on the test-results, so
        // we need those properties to be tested
        // before we conduct the RNG-Probe latestReport = report;
        this.latestReport = report;

    }

    private Config generateTls13BaseConfig() {
        Config tlsConfig = getScannerConfig().createConfig();
        tlsConfig.setQuickReceive(true);
        tlsConfig.setDefaultClientSupportedCipherSuites(CipherSuite.getImplementedTls13CipherSuites());
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.TLS13);
        tlsConfig.setSupportedVersions(ProtocolVersion.TLS13);
        tlsConfig.setEnforceSettings(false);
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        tlsConfig.setAddECPointFormatExtension(false);
        tlsConfig.setAddEllipticCurveExtension(true);
        tlsConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsConfig.setAddSupportedVersionsExtension(true);
        tlsConfig.setAddKeyShareExtension(true);
        tlsConfig.setAddServerNameIndicationExtension(true);
        tlsConfig.setUseFreshRandom(true);

        List<SignatureAndHashAlgorithm> algos = SignatureAndHashAlgorithm.getTls13SignatureAndHashAlgorithms();
        tlsConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(algos);

        return tlsConfig;
    }

    private Config generateBaseConfig() {
        // TODO make sure we use the highest version possible
        // TODO prefer aes over 3des
        Config config = getScannerConfig().createConfig();

        config.setAddServerNameIndicationExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddECPointFormatExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddRenegotiationInfoExtension(false);
        config.setUseFreshRandom(true);
        config.setStopActionsAfterFatal(true);
        config.setAddServerNameIndicationExtension(true);
        config.setDefaultClientSessionId(new byte[0]);
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        config.setStopActionsAfterWarning(true);
        config.setQuickReceive(true);
        config.setEarlyStop(true);

        List<NamedGroup> supportedGroups = new LinkedList<>();
        for (NamedGroup group : latestReport.getSupportedNamedGroups()) {
            if (!group.name().contains("FFDHE") && !group.name().contains(NamedGroup.ECDH_X25519.name())
                && !group.name().contains(NamedGroup.ECDH_X448.name())) {
                supportedGroups.add(group);
            }
        }
        if (!supportedGroups.isEmpty()) {
            config.setDefaultClientNamedGroups(supportedGroups);
        }

        return config;
    }

    private void collectData(int numberOfHandshakes) {
        List<State> stateList = new LinkedList<>();
        for (int i = 0; i < numberOfHandshakes; i++) {
            Config config;
            if (highestVersion.isTLS13()) {
                config = generateTls13BaseConfig();
            } else {
                config = generateBaseConfig();
            }
            if (supportsExtendedRandom) {
                config.setAddExtendedRandomExtension(true);
            }
            WorkflowTrace workflowTrace = new WorkflowConfigurationFactory(config)
                .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
            // TODO we should only do this when we are testing https
            config.setHttpsParsingEnabled(true);
            workflowTrace.addTlsAction(new SendAction(new HttpsRequestMessage(config)));
            workflowTrace.addTlsAction(new ReceiveAction(new HttpsResponseMessage(config)));
            State state = new State(config, workflowTrace);
            stateList.add(state);
        }

        executeState(stateList);

        for (State state : stateList) {
            extractRandoms(state);
            extractSessionIds(state);
            extractCbcIvs(state);
        }

        if (highestVersion.isTLS13()) {
            stateList = new LinkedList<>();
            for (int i = 0; i < numberOfHandshakes; i++) {
                Config config = generateBaseConfig();
                if (supportsExtendedRandom) {
                    config.setAddExtendedRandomExtension(true);
                }
                WorkflowTrace workflowTrace = new WorkflowConfigurationFactory(config)
                    .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT);
                // TODO we should only do this when we are testing https
                config.setHttpsParsingEnabled(true);
                workflowTrace.addTlsAction(new SendAction(new HttpsRequestMessage(config)));
                workflowTrace.addTlsAction(new ReceiveAction(new HttpsResponseMessage(config)));
                State state = new State(config, workflowTrace);
                stateList.add(state);
            }

            executeState(stateList);
            for (State state : stateList) {
                extractCbcIvs(state);
            }
        }
    }

    private void extractRandoms(State state) {
        // Extract randoms
        byte[] random = state.getTlsContext().getServerRandom();
        if (random != null) {
            if (usesUnixTime) {
                byte[] timeLessServerRandom = Arrays.copyOfRange(random, HandshakeByteLength.UNIX_TIME, random.length);
                extractedRandomList.add(new ComparableByteArray(timeLessServerRandom));
            } else {
                extractedRandomList.add(new ComparableByteArray(random));
            }
        }
    }

    private void extractSessionIds(State state) {
        // Extract Session ID's
        if (!state.getTlsContext().getSessionList().isEmpty()) {
            byte[] sessionId = state.getTlsContext().getSessionList().get(0).getSessionId();
            extractedIVList.add(new ComparableByteArray(sessionId));
        }
    }

    private void extractCbcIvs(State state) {
        List<AbstractRecord> allReceivedRecords = WorkflowTraceUtil.getAllReceivedRecords(state.getWorkflowTrace());
        for (AbstractRecord record : allReceivedRecords) {
            if (record instanceof Record) {
                if (((Record) record).getComputations() != null
                    && ((Record) record).getComputations().getCbcInitialisationVector() != null) {
                    ModifiableByteArray cbcInitialisationVector =
                        ((Record) record).getComputations().getCbcInitialisationVector();
                    extractedIVList.add(new ComparableByteArray(cbcInitialisationVector.getValue()));
                }
            }

        }
    }

    /**
     * Checks if the Host utilities Unix time or similar counters for Server Randoms.
     *
     * @return TRUE if the server is probably using a counter in its server random.
     */
    private boolean checkForUnixTime() {
        Config config = generateBaseConfig();

        config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);

        Integer lastUnixTime = null;
        Integer serverUnixTime = null;
        int matchCounter = 0;

        for (int i = 0; i < UNIX_TIME_CONNECTIONS; i++) {

            State state = new State(config);
            long startTime = System.currentTimeMillis();
            executeState(state);
            long endTime = System.currentTimeMillis();

            // current time is in milliseconds
            long duration = (endTime - startTime) / 1000;

            byte[] serverRandom = state.getTlsContext().getServerRandom();
            LOGGER.debug("Duration: " + duration);
            if (lastUnixTime != null) {
                if (serverRandom != null) {
                    byte[] unixTimeStamp = new byte[4];
                    System.arraycopy(serverRandom, 0, unixTimeStamp, 0, HandshakeByteLength.UNIX_TIME);
                    serverUnixTime = ArrayConverter.bytesToInt(unixTimeStamp);
                    LOGGER.debug("Previous Time: " + lastUnixTime);
                    LOGGER.debug("Current Time: " + serverUnixTime);
                    if (lastUnixTime - (UNIX_TIME_ALLOWED_DEVIATION + duration) <= serverUnixTime) {
                        if (lastUnixTime + (UNIX_TIME_ALLOWED_DEVIATION + duration) >= serverUnixTime) {
                            matchCounter++;
                        }
                    }
                    lastUnixTime = serverUnixTime;
                }
            }
        }

        if (matchCounter >= MINIMUM_MATCH_COUNTER) {
            LOGGER.debug("ServerRandom utilizes UnixTimestamps.");
            return true;
        } else {
            LOGGER.debug("No UnixTimestamps detected.");
            return false;
        }
    }
}
