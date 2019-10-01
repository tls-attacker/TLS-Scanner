/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.DrownCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.impl.DrownAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.DrownResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;

public class DrownProbe extends TlsProbe {

    public DrownProbe(ScannerConfig scannerConfig, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.DROWN, scannerConfig, 8);
    }

    @Override
    public ProbeResult executeTest() {
        DrownCommandConfig drownCommandConfig = new DrownCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) drownCommandConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        StarttlsDelegate starttlsDelegate = (StarttlsDelegate) drownCommandConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
        DrownAttacker attacker = new DrownAttacker(drownCommandConfig, drownCommandConfig.createConfig());
        DrownVulnerabilityType drownVulnerabilityType = attacker.getDrownVulnerabilityType();
        return new DrownResult(drownVulnerabilityType);
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
        return new DrownResult(null);
    }
}
