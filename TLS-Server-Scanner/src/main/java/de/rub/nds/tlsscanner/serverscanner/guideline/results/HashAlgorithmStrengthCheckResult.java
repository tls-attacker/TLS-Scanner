/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import java.util.Objects;

public class HashAlgorithmStrengthCheckResult extends GuidelineCheckResult {

    private final HashAlgorithm hashAlgorithm;

    public HashAlgorithmStrengthCheckResult(TestResult result, HashAlgorithm hashAlgorithm) {
        super(result);
        this.hashAlgorithm = hashAlgorithm;
    }

    @Override
    public String display() {
        if (Objects.equals(TestResults.TRUE, getResult())) {
            return "Used Hash Algorithms are strong enough.";
        }
        return hashAlgorithm + " is too weak";
    }
}
