/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
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
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.result.CipherSuiteResult;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class CipherSuiteProbe
        extends TlsClientProbe<ClientScannerConfig, ClientReport, CipherSuiteResult<ClientReport>> {

    private final List<ProtocolVersion> protocolVersions;

    public CipherSuiteProbe(ParallelExecutor executor, ClientScannerConfig scannerConfig) {
        super(executor, TlsProbeType.CIPHER_SUITE, scannerConfig);
        protocolVersions = new LinkedList<>();
    }

    @Override
    public CipherSuiteResult executeTest() {
        List<VersionSuiteListPair> versionSuitePairs = new LinkedList<>();
        for (ProtocolVersion version : protocolVersions) {
            LOGGER.debug("Testing cipher suites for version {}", version);

            Config config;
            if (version.isTLS13()) {
                config = getTls13Config();
            } else {
                config = getBaseConfig();
            }
            config.setHighestProtocolVersion(version);
            config.setDefaultSelectedProtocolVersion(version);
            config.setEnforceSettings(true);

            List<CipherSuite> toTestList = getToTestCipherSuitesByVersion(version);
            List<CipherSuite> supportedSuites = new LinkedList<>();

            while (!toTestList.isEmpty()) {
                CipherSuite currentSuite = toTestList.get(0);
                config.setDefaultServerSupportedCipherSuites(toTestList);
                config.setDefaultSelectedCipherSuite(currentSuite);
                WorkflowTrace trace =
                        new WorkflowConfigurationFactory(config)
                                .createWorkflowTrace(
                                        WorkflowTraceType.HELLO, RunningModeType.SERVER);
                trace.addTlsAction(new ReceiveTillAction(new FinishedMessage()));

                State state = new State(config, trace);
                executeState(state);
                if (state.getWorkflowTrace().executedAsPlanned()) {
                    supportedSuites.add(currentSuite);
                }
                toTestList.remove(currentSuite);
            }

            if (!supportedSuites.isEmpty()) {
                versionSuitePairs.add(new VersionSuiteListPair(version, supportedSuites));
            }
        }
        return new CipherSuiteResult(versionSuitePairs);
    }

    private List<CipherSuite> getToTestCipherSuitesByVersion(ProtocolVersion version) {
        if (version == ProtocolVersion.SSL3) {
            return (List<CipherSuite>) CipherSuite.SSL3_SUPPORTED_CIPHERSUITES;
        }
        if (version == ProtocolVersion.TLS13) {
            return CipherSuite.getImplementedTls13CipherSuites();
        }
        List<CipherSuite> realCipherSuites =
                Arrays.asList(CipherSuite.values()).stream()
                        .filter(suite -> suite.isRealCipherSuite())
                        .collect(Collectors.toList());
        switch (scannerConfig.getScanDetail()) {
            case QUICK:
            case NORMAL:
                return filterPskCipherSuites(filterForVersionSupported(realCipherSuites, version));
            case DETAILED:
                return filterForVersionSupported(realCipherSuites, version);
            case ALL:
            default:
                return realCipherSuites;
        }
    }

    private List<CipherSuite> filterForVersionSupported(
            Collection<CipherSuite> suites, ProtocolVersion version) {
        return suites.stream()
                .filter(suite -> suite.isSupportedInProtocol(version))
                .collect(Collectors.toList());
    }

    private List<CipherSuite> filterPskCipherSuites(Collection<CipherSuite> suites) {
        return suites.stream().filter(suite -> !suite.isPsk()).collect(Collectors.toList());
    }

    private Config getBaseConfig() {
        Config config = scannerConfig.createConfig();
        config.setStopReceivingAfterFatal(true);
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        config.setStopTraceAfterUnexpected(true);
        config.setStopActionsAfterWarning(true);
        config.setAddRenegotiationInfoExtension(false);
        return config;
    }

    private Config getTls13Config() {
        Config config = getBaseConfig();
        config.setSupportedVersions(ProtocolVersion.TLS13);
        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        return config;
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return report.isProbeAlreadyExecuted(TlsProbeType.PROTOCOL_VERSION);
    }

    @Override
    public CipherSuiteResult getCouldNotExecuteResult() {
        return new CipherSuiteResult(null);
    }

    @Override
    public void adjustConfig(ClientReport report) {
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.DTLS10);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.DTLS12);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_SSL_3) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.SSL3);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.TLS10);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.TLS11);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.TLS12);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3) == TestResults.TRUE) {
            protocolVersions.add(ProtocolVersion.TLS13);
        }
    }
}
