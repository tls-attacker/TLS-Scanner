/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;

import java.util.ArrayList;
import java.util.List;

public class CertificateGuidelineCheckResult extends GuidelineCheckResult {

    private final List<GuidelineCheckResult> results = new ArrayList<>();

    public CertificateGuidelineCheckResult() {
        super(TestResults.UNCERTAIN);
    }

    @Override
    public String display() {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < results.size(); i++) {
            GuidelineCheckResult result = this.results.get(i);
            stringBuilder.append("Certificate Check #").append(i + 1).append('\n');
            stringBuilder.append(result.display()).append('\n');
        }
        return stringBuilder.toString();
    }

    public void addResult(GuidelineCheckResult result) {
        this.results.add(result);
    }

    public List<GuidelineCheckResult> getResults() {
        return results;
    }
}
