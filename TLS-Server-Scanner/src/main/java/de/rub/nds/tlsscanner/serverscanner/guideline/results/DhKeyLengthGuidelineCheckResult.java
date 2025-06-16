/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;

public class DhKeyLengthGuidelineCheckResult extends GuidelineCheckResult {

    private final int weakestDhStrength;
    private final int minimumDhKeyLength;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private DhKeyLengthGuidelineCheckResult() {
        super(null, null);
        this.weakestDhStrength = 0;
        this.minimumDhKeyLength = 0;
    }

    public DhKeyLengthGuidelineCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            int weakestDhStrength,
            int minimumDhKeyLength) {
        super(checkName, adherence);
        this.weakestDhStrength = weakestDhStrength;
        this.minimumDhKeyLength = minimumDhKeyLength;
    }

    public int getWeakestDhStrength() {
        return weakestDhStrength;
    }

    public int getMinimumDhKeyLength() {
        return minimumDhKeyLength;
    }

    @Override
    public String toString() {
        return String.format("Weakest DH size %d<%d", weakestDhStrength, minimumDhKeyLength);
    }
}
