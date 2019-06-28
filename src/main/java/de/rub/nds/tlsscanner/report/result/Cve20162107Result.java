/**
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
import de.rub.nds.tlsscanner.report.result.ProbeResult;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class Cve20162107Result extends ProbeResult {

    private Boolean vulnerable;

    public Cve20162107Result(Boolean vulnerable) {
        super(ProbeType.CVE20162107);
        this.vulnerable = vulnerable;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setCve20162107Vulnerable(vulnerable);
    }

}
