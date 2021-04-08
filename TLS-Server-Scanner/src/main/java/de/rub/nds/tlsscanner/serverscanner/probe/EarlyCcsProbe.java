/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.impl.EarlyCCSAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.EarlyCcsResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;

public class EarlyCcsProbe extends TlsProbe {

    public EarlyCcsProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.EARLY_CCS, scannerConfig);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            EarlyCCSCommandConfig earlyCcsCommandConfig =
                new EarlyCCSCommandConfig(getScannerConfig().getGeneralDelegate());
            ClientDelegate delegate = (ClientDelegate) earlyCcsCommandConfig.getDelegate(ClientDelegate.class);
            delegate.setHost(getScannerConfig().getClientDelegate().getHost());
            delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
            StarttlsDelegate starttlsDelegate =
                (StarttlsDelegate) earlyCcsCommandConfig.getDelegate(StarttlsDelegate.class);
            starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
            EarlyCCSAttacker attacker =
                new EarlyCCSAttacker(earlyCcsCommandConfig, earlyCcsCommandConfig.createConfig());
            EarlyCcsVulnerabilityType earlyCcsVulnerabilityType = attacker.getEarlyCcsVulnerabilityType();
            return new EarlyCcsResult(earlyCcsVulnerabilityType);
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new EarlyCcsResult(null);
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new EarlyCcsResult(null);
    }
}
