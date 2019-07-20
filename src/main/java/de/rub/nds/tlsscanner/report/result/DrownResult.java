/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
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
        report.putResult(vulnType);
    }

}
