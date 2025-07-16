/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

public class VersionDependentTestResults extends VersionDependentSummarizableResult<TestResults> {

    @JsonProperty("explicitSummary")
    @JsonTypeInfo(
            use = JsonTypeInfo.Id.CLASS,
            include = JsonTypeInfo.As.PROPERTY,
            property = "@class")
    protected final TestResults explicitSummary;

    public VersionDependentTestResults(
            @JsonProperty("explicitSummary") TestResults explicitSummary) {
        this.explicitSummary = explicitSummary;
    }

    public VersionDependentTestResults() {
        this(null);
    }

    // helper function
    public void putResult(ProtocolVersion version, boolean result) {
        if (isExplicitSummary()) {
            throw new UnsupportedOperationException("Cannot add results to a summarized result");
        }
        results.put(version, TestResults.of(result));
    }

    @Override
    public void putResult(ProtocolVersion version, TestResults result) {
        if (isExplicitSummary()) {
            throw new UnsupportedOperationException("Cannot add results to a summarized result");
        }
        super.putResult(version, result);
    }

    @Override
    @JsonIgnore
    public boolean isExplicitSummary() {
        return explicitSummary != null;
    }

    @Override
    public TestResults getSummarizedResult() {
        if (isExplicitSummary()) {
            return explicitSummary;
        }
        return super.getSummarizedResult();
    }
}
