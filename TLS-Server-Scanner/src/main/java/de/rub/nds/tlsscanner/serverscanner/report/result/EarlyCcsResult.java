/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class EarlyCcsResult extends ProbeResult {

    private EarlyCcsVulnerabilityType earlyCcsVulnerabilityType;

    public EarlyCcsResult(EarlyCcsVulnerabilityType earlyCcsVulnerabilityType) {
        super(ProbeType.EARLY_CCS);
        this.earlyCcsVulnerabilityType = earlyCcsVulnerabilityType;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(earlyCcsVulnerabilityType);
    }

}
