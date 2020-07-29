/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author robert
 */
public class ResumptionResult extends ProbeResult {

    private TestResult supportsResumption;

    public ResumptionResult(TestResult supportsResumption) {
        super(ProbeType.RESUMPTION);
        this.supportsResumption = supportsResumption;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.SUPPORTS_SESSION_IDS, supportsResumption);
    }

}
