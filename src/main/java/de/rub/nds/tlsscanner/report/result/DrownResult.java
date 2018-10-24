package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;

public class DrownResult extends ProbeResult {

    private final DrownVulnerabilityType vulnType;

    public DrownResult(DrownVulnerabilityType vulnType) {
        super(ProbeType.DROWN);
        this.vulnType = vulnType;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setDrownVulnerable(vulnType);
    }

}
