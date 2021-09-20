/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.probe;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsscanner.clientscanner.probe.result.VersionResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import java.util.LinkedList;
import java.util.List;

public class VersionProbe extends TlsProbe<ClientReport, VersionResult> {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<CipherSuite> clientAdvertisedCipherSuites = null;

    public VersionProbe(ParallelExecutor executor, ScannerConfig scannerConfig) {
        super(executor, TlsProbeType.PROTOCOL_VERSION, scannerConfig);
    }

    public Config getTls13Config() {
        Config config = getScannerConfig().createConfig();
        List<CipherSuite> tls13CipherSuites = new LinkedList<>();
        for (CipherSuite suite : clientAdvertisedCipherSuites) {
            if (suite.isTLS13()) {
                tls13CipherSuites.add(suite);
            }
        }
        config.setDefaultServerSupportedCipherSuites(tls13CipherSuites);
        config.setDefaultSelectedCipherSuite(tls13CipherSuites.get(0));
        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        config.setAddRenegotiationInfoExtension(false);
        return config;
    }

    public CipherSuite getSuiteableCipherSuite(ProtocolVersion version, List<CipherSuite> suiteList) {
        for (CipherSuite suite : suiteList) {
            if (suite.isSupportedInProtocol(version)) {
                return suite;
            }
        }
        LOGGER.warn("No suiteable cipher suite found for " + version + ". Using " + suiteList.get(0) + " instead.");
        return suiteList.get(0);
    }

    @Override
    public VersionResult executeTest() {
        ProtocolVersion[] versionsToTest = { ProtocolVersion.SSL3, ProtocolVersion.TLS10, ProtocolVersion.TLS11,
            ProtocolVersion.TLS12, ProtocolVersion.TLS13 };
        List<ProtocolVersion> supportedVersions = new LinkedList<>();
        List<ProtocolVersion> unsupportedVersions = new LinkedList<>();
        for (ProtocolVersion version : versionsToTest) {
            LOGGER.debug("Testing version {}", version);
            Config config;
            if (version.isTLS13()) {
                config = getTls13Config();
            } else {
                config = getScannerConfig().createConfig();
            }
            config.setDefaultServerSupportedCipherSuites(clientAdvertisedCipherSuites);
            config.setDefaultSelectedCipherSuite(getSuiteableCipherSuite(version, clientAdvertisedCipherSuites));
            config.setHighestProtocolVersion(version);
            config.setDefaultSelectedProtocolVersion(version);
            WorkflowTrace trace = new WorkflowConfigurationFactory(config)
                .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.SERVER);
            trace.removeTlsAction(trace.getTlsActions().size() - 1); // remove last action as it is not needed to
                                                                     // confirm success
            State state = new State(config, trace);
            if (state.getWorkflowTrace().executedAsPlanned()) {
                supportedVersions.add(version);
            } else {
                unsupportedVersions.add(version);
            }
        }
        return new VersionResult(supportedVersions, unsupportedVersions);
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return report.getAdvertisedCipherSuites() != null;

    }

    @Override
    public VersionResult getCouldNotExecuteResult() {
        return new VersionResult(null, null);
    }

    @Override
    public void adjustConfig(ClientReport report) {
        this.clientAdvertisedCipherSuites = report.getAdvertisedCipherSuites();
    }
}
