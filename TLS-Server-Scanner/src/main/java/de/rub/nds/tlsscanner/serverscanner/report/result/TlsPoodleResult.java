/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public class TlsPoodleResult extends ProbeResult {

    private final TestResult vulnerable;

    public TlsPoodleResult(TestResult vulnerable) {
        super(ProbeType.TLS_POODLE);
        this.vulnerable = vulnerable;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.VULNERABLE_TO_TLS_POODLE, vulnerable);
    }

}
