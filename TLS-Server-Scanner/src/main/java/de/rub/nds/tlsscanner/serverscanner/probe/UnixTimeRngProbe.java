/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.UnixTimeRngTestResult;

import java.util.LinkedList;
import java.util.List;

/**
 * @author Dennis Ziebart - dziebart@mail.uni-paderborn.de
 */
public class UnixTimeRngProbe extends TlsProbe {

    // How much the time is allowed to deviate between two handshakes when
    // viewed using UNIX time prefix
    private final int UNIX_TIME_ALLOWED_DEVIATION = 500;
    // Amount of retries allowed when failing to receive ServerHello messages in
    // the Unix Time test
    private final int UNIX_TIME_CONNECTIONS = 5;
    // How many of the 3 ServerHello randoms should pass the Unix Time test at
    // minimum.
    private final int MINIMUM_MATCH_COUNTER = 2;

    private SiteReport latestReport;

    public UnixTimeRngProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.RNG, config);
    }

    @Override
    public ProbeResult executeTest() {
        return new UnixTimeRngTestResult(checkForUnixTime());
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_3) != TestResult.NOT_TESTED_YET
            && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2) != TestResult.NOT_TESTED_YET
            && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1) != TestResult.NOT_TESTED_YET
            && report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0) != TestResult.NOT_TESTED_YET
            && report.getResult(AnalyzedProperty.SUPPORTS_RSA) != TestResult.NOT_TESTED_YET
            && report.getResult(AnalyzedProperty.SUPPORTS_DH) != TestResult.NOT_TESTED_YET
            && report.getResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH) != TestResult.NOT_TESTED_YET
            && report.getResult(AnalyzedProperty.GROUPS_DEPEND_ON_CIPHER) != TestResult.NOT_TESTED_YET;
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new UnixTimeRngTestResult(TestResult.COULD_NOT_TEST);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        this.latestReport = report;
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

    /**
     * Checks if the Host utilities Unix time or similar counters for Server Randoms.
     *
     * @return TRUE if the server is probably using a counter in its server random.
     */
    private TestResult checkForUnixTime() {
        Config config = generateBaseConfig();

        config.setWorkflowTraceType(WorkflowTraceType.SHORT_HELLO);

        Integer lastUnixTime = null;
        int serverUnixTime;
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
            } else {
                if (serverRandom != null) {
                    byte[] unixTimeStamp = new byte[4];
                    System.arraycopy(serverRandom, 0, unixTimeStamp, 0, HandshakeByteLength.UNIX_TIME);
                    lastUnixTime = ArrayConverter.bytesToInt(unixTimeStamp);
                }
            }
        }

        if (matchCounter >= MINIMUM_MATCH_COUNTER) {
            LOGGER.debug("ServerRandom utilizes UnixTimestamps.");
            return TestResult.TRUE;
        } else {
            LOGGER.debug("No UnixTimestamps detected.");
            return TestResult.FALSE;
        }
    }
}
