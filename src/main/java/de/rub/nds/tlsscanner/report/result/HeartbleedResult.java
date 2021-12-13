/*
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class HeartbleedResult extends ProbeResult {

    private Boolean vulnerable;

    public HeartbleedResult(Boolean vulnerable) {
        super(ProbeType.HEARTBLEED);
        this.vulnerable = vulnerable;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setHeartbleedVulnerable(vulnerable);
    }
}
