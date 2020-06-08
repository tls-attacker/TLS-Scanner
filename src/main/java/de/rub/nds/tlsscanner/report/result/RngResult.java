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

public class RngResult extends ProbeResult {

    private boolean rng_extracted = false;

    public RngResult(boolean rng_extracted) {
        super(ProbeType.RNG);
        this.rng_extracted = rng_extracted;
    }

    @Override
    public void mergeData(SiteReport report) {

        if (rng_extracted) {
            report.putResult(AnalyzedProperty.RNG_EXTRACTED, TestResult.TRUE);
        }

    }
}
