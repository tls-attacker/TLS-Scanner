/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.TLSPoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.TLSPoodleAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResults;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.requirements.ProbeRequirement;

public class TlsPoodleProbe extends TlsProbe {

    private TestResult vulnerable;

    public TlsPoodleProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.TLS_POODLE, config);
        super.properties.add(AnalyzedProperty.VULNERABLE_TO_TLS_POODLE);
    }

    @Override
    public void executeTest() {
        TLSPoodleCommandConfig poodleCommandConfig =
            new TLSPoodleCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) poodleCommandConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        if (getScannerConfig().getDtlsDelegate().isDTLS()) {
            ProtocolVersionDelegate protocolVersionDelegate =
                (ProtocolVersionDelegate) poodleCommandConfig.getDelegate(ProtocolVersionDelegate.class);
            protocolVersionDelegate.setProtocolVersion(ProtocolVersion.DTLS12);
        }
        StarttlsDelegate starttlsDelegate = (StarttlsDelegate) poodleCommandConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
        TLSPoodleAttacker attacker = new TLSPoodleAttacker(poodleCommandConfig, poodleCommandConfig.createConfig());
        this.vulnerable = attacker.isVulnerable() == true ? TestResults.TRUE : TestResults.FALSE;
    }

    @Override
    protected ProbeRequirement getRequirements(SiteReport report) {
    	return new ProbeRequirement(report).requireAnalyzedProperties(AnalyzedProperty.SUPPORTS_BLOCK_CIPHERS);		
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public void getCouldNotExecuteResult() {
        this.vulnerable = TestResults.COULD_NOT_TEST;
    }

	@Override
	protected void mergeData(SiteReport report) {
        super.setPropertyReportValue(AnalyzedProperty.VULNERABLE_TO_TLS_POODLE, this.vulnerable);		
	}
}
