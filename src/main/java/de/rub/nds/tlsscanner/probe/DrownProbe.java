package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.Cve20162107CommandConfig;
import de.rub.nds.tlsattacker.attacks.config.DrownCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.impl.Cve20162107Attacker;
import de.rub.nds.tlsattacker.attacks.impl.DrownAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.Cve20162107Result;
import de.rub.nds.tlsscanner.report.result.DrownResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;

public class DrownProbe extends TlsProbe {

    public DrownProbe(ScannerConfig scannerConfig) {
        super(ProbeType.DROWN, scannerConfig, 8);
    }

    @Override
    public ProbeResult executeTest() {
        DrownCommandConfig drownCommandConfig = new DrownCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) drownCommandConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        DrownAttacker attacker = new DrownAttacker(drownCommandConfig);
        DrownVulnerabilityType drownVulnerabilityType = attacker.getDrownVulnerabilityType();
        return new DrownResult(drownVulnerabilityType);
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return true;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new DrownResult(DrownVulnerabilityType.UNKNOWN);
    }

}
