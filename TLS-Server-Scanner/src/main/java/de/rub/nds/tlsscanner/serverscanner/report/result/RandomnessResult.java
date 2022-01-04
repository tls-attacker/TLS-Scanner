/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class RandomnessResult extends ProbeResult {

    public RandomnessResult() {
        super(ProbeType.RANDOMNESS);
    }

    @Override
    public void mergeData(SiteReport report) {
        // Nothing to do here - all data analysis is done in the after probe
    }
}
