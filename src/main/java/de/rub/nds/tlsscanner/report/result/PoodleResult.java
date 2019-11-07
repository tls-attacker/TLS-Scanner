/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class PoodleResult extends ProbeResult {

    private TestResult vulnerable;

    public PoodleResult(TestResult vulnerable) {
        super(ProbeType.POODLE);
        this.vulnerable = vulnerable;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.VULNERABLE_TO_POODLE, vulnerable);
    }

}
