/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.probe.result.TestResults;
import java.util.stream.Collectors;

public class VersionDependentSummarizableResult<T extends SummarizableTestResult>
        extends VersionDependentResult<T> implements SummarizableTestResult {

    protected final TestResultsMerger merger;

    public VersionDependentSummarizableResult(TestResultsMerger merger) {
        this.merger = merger;
    }

    @Override
    public boolean isExplicitSummary() {
        return false;
    }

    @Override
    public TestResults getSummarizedResult() {
        return this.merger.merge(
                results.values().stream()
                        .map(SummarizableTestResult::getSummarizedResult)
                        .collect(Collectors.toList()));
    }

    @Override
    public String getName() {
        return SummarizableTestResult.super.getName();
    }
}
