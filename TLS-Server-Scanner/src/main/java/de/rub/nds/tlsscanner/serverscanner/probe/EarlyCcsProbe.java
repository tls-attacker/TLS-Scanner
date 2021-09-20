/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.impl.EarlyCCSAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.probe.result.EarlyCcsResult;
import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;

public class EarlyCcsProbe extends TlsProbe<SiteReport, EarlyCcsResult> {

    public EarlyCcsProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, TlsProbeType.EARLY_CCS, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        EarlyCCSCommandConfig earlyCcsCommandConfig =
            new EarlyCCSCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) earlyCcsCommandConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        StarttlsDelegate starttlsDelegate =
            (StarttlsDelegate) earlyCcsCommandConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
        EarlyCCSAttacker attacker = new EarlyCCSAttacker(earlyCcsCommandConfig, earlyCcsCommandConfig.createConfig());
        EarlyCcsVulnerabilityType earlyCcsVulnerabilityType = attacker.getEarlyCcsVulnerabilityType();
        return new EarlyCcsResult(earlyCcsVulnerabilityType);
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public EarlyCcsResult getCouldNotExecuteResult() {
        return new EarlyCcsResult(null);
    }

}
