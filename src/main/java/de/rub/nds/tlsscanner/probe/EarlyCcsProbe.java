package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.impl.EarlyCCSAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.DrownResult;
import de.rub.nds.tlsscanner.report.result.EarlyCcsResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;

public class EarlyCcsProbe extends TlsProbe {

    public EarlyCcsProbe(ScannerConfig scannerConfig) {
        super(ProbeType.EARLY_CCS, scannerConfig, 8);
    }

    @Override
    public ProbeResult executeTest() {
        EarlyCCSCommandConfig earlyCcsCommandConfig = new EarlyCCSCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) earlyCcsCommandConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        EarlyCCSAttacker attacker = new EarlyCCSAttacker(earlyCcsCommandConfig, earlyCcsCommandConfig.createConfig());
        EarlyCcsVulnerabilityType earlyCcsVulnerabilityType = attacker.getEarlyCcsVulnerabilityType();
        return new EarlyCcsResult(earlyCcsVulnerabilityType);
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
        return new EarlyCcsResult(null);
    }

}
