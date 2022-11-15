/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.result.ProtocolVersionResult;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class ProtocolVersionProbe
        extends TlsClientProbe<
                ClientScannerConfig, ClientReport, ProtocolVersionResult<ClientReport>> {

    private List<ProtocolVersion> toTestList;
    private List<CipherSuite> clientAdvertisedCipherSuites = null;

    public ProtocolVersionProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.PROTOCOL_VERSION, scannerConfig);
    }

    @Override
    public ProtocolVersionResult executeTest() {
        List<ProtocolVersion> supportedVersions = new LinkedList<>();
        List<ProtocolVersion> unsupportedVersions = new LinkedList<>();
        for (ProtocolVersion version : toTestList) {
            LOGGER.debug("Testing version {}", version);

            Config config;
            if (version.isTLS13()) {
                config = getTls13Config();
            } else {
                config = getBaseConfig();
            }
            config.setSupportedVersions(version);
            config.setHighestProtocolVersion(version);
            config.setDefaultSelectedProtocolVersion(version);
            config.setDefaultSelectedCompressionMethod(CompressionMethod.NULL);
            config.setEnforceSettings(true);

            List<CipherSuite> suitableCiphersuites = getSuitableCipherSuites(version);
            config.setDefaultServerSupportedCipherSuites(suitableCiphersuites);

            if (testProtocolVersion(config, suitableCiphersuites)) {
                supportedVersions.add(version);
            } else {
                unsupportedVersions.add(version);
            }
        }
        return new ProtocolVersionResult(supportedVersions, unsupportedVersions);
    }

    private List<CipherSuite> getSuitableCipherSuites(ProtocolVersion version) {
        List<CipherSuite> suitableCiphersuites =
                clientAdvertisedCipherSuites.stream()
                        .filter(suite -> suite.isSupportedInProtocol(version))
                        .collect(Collectors.toList());
        if (suitableCiphersuites.isEmpty()) {
            CipherSuite fallbackCipherSuite;
            List<CipherSuite> nonPskCipherSuites =
                    clientAdvertisedCipherSuites.stream()
                            .filter(suite -> !suite.isPsk())
                            .collect(Collectors.toList());
            if (!nonPskCipherSuites.isEmpty()) {
                fallbackCipherSuite = nonPskCipherSuites.get(0);
            } else {
                fallbackCipherSuite = clientAdvertisedCipherSuites.get(0);
            }
            LOGGER.warn(
                    "No suitable cipher suite found for {}. Using {} instead.",
                    version,
                    fallbackCipherSuite);
            suitableCiphersuites.add(fallbackCipherSuite);
        }
        return suitableCiphersuites;
    }

    private boolean testProtocolVersion(Config config, List<CipherSuite> suitableCiphersuites) {
        for (CipherSuite currentCipher : suitableCiphersuites) {
            config.setDefaultSelectedCipherSuite(currentCipher);
            WorkflowTrace trace =
                    new WorkflowConfigurationFactory(config)
                            .createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.SERVER);
            trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

            State state = new State(config, trace);
            executeState(state);
            if (state.getWorkflowTrace().executedAsPlanned()) {
                return true;
            }
        }
        return false;
    }

    private Config getBaseConfig() {
        Config config = scannerConfig.createConfig();
        config.setEarlyStop(true);
        config.setQuickReceive(true);
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        config.setAddRenegotiationInfoExtension(false);
        return config;
    }

    private Config getTls13Config() {
        Config config = getBaseConfig();
        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        return config;
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return report.isProbeAlreadyExecuted(TlsProbeType.BASIC)
                && report.getClientAdvertisedCipherSuites() != null;
    }

    @Override
    public ProtocolVersionResult getCouldNotExecuteResult() {
        return new ProtocolVersionResult(null, null);
    }

    @Override
    public void adjustConfig(ClientReport report) {
        toTestList = new LinkedList<>();
        if (scannerConfig.getDtlsDelegate().isDTLS()) {
            toTestList.add(ProtocolVersion.DTLS10_DRAFT);
            toTestList.add(ProtocolVersion.DTLS10);
            toTestList.add(ProtocolVersion.DTLS12);
        } else {
            toTestList.add(ProtocolVersion.SSL2);
            toTestList.add(ProtocolVersion.SSL3);
            toTestList.add(ProtocolVersion.TLS10);
            toTestList.add(ProtocolVersion.TLS11);
            toTestList.add(ProtocolVersion.TLS12);
            toTestList.add(ProtocolVersion.TLS13);
        }
        clientAdvertisedCipherSuites =
                report.getClientAdvertisedCipherSuites().stream()
                        .filter(suite -> suite.isRealCipherSuite())
                        .collect(Collectors.toList());
    }
}
