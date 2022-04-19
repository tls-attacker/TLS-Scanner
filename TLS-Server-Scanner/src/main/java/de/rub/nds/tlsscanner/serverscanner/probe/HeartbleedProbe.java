/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.HeartbleedAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.CipherSuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class HeartbleedProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private List<CipherSuite> supportedCiphers;
    private TestResult vulnerable;

    public HeartbleedProbe(ServerScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.HEARTBLEED, config);
        super.register(TlsAnalyzedProperty.VULNERABLE_TO_HEARTBLEED);
    }

    @Override
    public void executeTest() {
        HeartbleedCommandConfig heartbleedConfig = new HeartbleedCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) heartbleedConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        if (getScannerConfig().getDtlsDelegate().isDTLS()) {
            ProtocolVersionDelegate protocolVersionDelegate =
                (ProtocolVersionDelegate) heartbleedConfig.getDelegate(ProtocolVersionDelegate.class);
            protocolVersionDelegate.setProtocolVersion(ProtocolVersion.DTLS12);
        }
        StarttlsDelegate starttlsDelegate = (StarttlsDelegate) heartbleedConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(getScannerConfig().getStarttlsDelegate().getStarttlsType());
        if (supportedCiphers != null) {
            CipherSuiteDelegate cipherSuiteDelegate =
                (CipherSuiteDelegate) heartbleedConfig.getDelegate(CipherSuiteDelegate.class);
            cipherSuiteDelegate.setCipherSuites(supportedCiphers);
        }
        HeartbleedAttacker attacker = new HeartbleedAttacker(heartbleedConfig, heartbleedConfig.createConfig());
        this.vulnerable = Objects.equals(attacker.isVulnerable(), Boolean.TRUE) ? TestResults.TRUE : TestResults.FALSE;
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        return new ProbeRequirement(report).requireProbeTypes(TlsProbeType.EXTENSIONS)
            .requireExtensionTyes(ExtensionType.HEARTBEAT);
    }

    @Override
    public void adjustConfig(ServerReport report) {
        if (report.getCipherSuites() != null && !report.getCipherSuites().isEmpty()) {
            supportedCiphers = new ArrayList<>(report.getCipherSuites());
        } else {
            supportedCiphers = CipherSuite.getImplemented();
        }
    }

    @Override
    public HeartbleedProbe getCouldNotExecuteResult() {
        this.vulnerable = TestResults.COULD_NOT_TEST;
        return this;
    }

    @Override
    protected void mergeData(ServerReport report) {
        super.put(TlsAnalyzedProperty.VULNERABLE_TO_HEARTBLEED, this.vulnerable);
    }
}
