/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.impl.EarlyCCSAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.probe.requirements.ProbeRequirement;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class EarlyCcsProbe extends TlsProbe<ServerScannerConfig, ServerReport> {

    private EarlyCcsVulnerabilityType earlyCcsVulnerabilityType;

    public EarlyCcsProbe(ServerScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.EARLY_CCS, scannerConfig);
        super.properties.add(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS);
    }

    @Override
    public void executeTest() {
        EarlyCCSCommandConfig earlyCcsCommandConfig =
            new EarlyCCSCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) earlyCcsCommandConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        StarttlsDelegate starttlsDelegate =
            (StarttlsDelegate) earlyCcsCommandConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
        EarlyCCSAttacker attacker = new EarlyCCSAttacker(earlyCcsCommandConfig, earlyCcsCommandConfig.createConfig());
        this.earlyCcsVulnerabilityType = attacker.getEarlyCcsVulnerabilityType();
    }

    @Override
    public void adjustConfig(ServerReport report) {
    }

    @Override
    public EarlyCcsProbe getCouldNotExecuteResult() {
        this.earlyCcsVulnerabilityType = null;
        return this;
    }

    @Override
    protected void mergeData(ServerReport report) {
        if (this.earlyCcsVulnerabilityType == null)
            super.setPropertyReportValue(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS, TestResults.COULD_NOT_TEST);
        else {
            switch (this.earlyCcsVulnerabilityType) {
                case VULN_EXPLOITABLE:
                case VULN_NOT_EXPLOITABLE:
                    super.setPropertyReportValue(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS, TestResults.TRUE);
                    break;
                case NOT_VULNERABLE:
                    super.setPropertyReportValue(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS, TestResults.FALSE);
                    break;
                case UNKNOWN:
                    super.setPropertyReportValue(TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS,
                        TestResults.COULD_NOT_TEST);
            }
        }
    }

    @Override
    protected Requirement getRequirements(ServerReport report) {
        return new ProbeRequirement(report);
    }
}
