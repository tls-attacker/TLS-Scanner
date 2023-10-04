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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.EnumMap;
import java.util.Map;

public class VersionDependentTestResult extends VersionDependentResult<TestResults> {
    // if this is deemed useful to reuse, maybe consider a more generic approach:
    // `MergeStrategy<ResultType>`
    // The enum below would become the class:
    // `TestResultsMergeStrategy implements MergeStrategy<TestResults>`

    public enum MergeStrategy {
        TRUE_PARTIAL_FALSE_OTHER(TestResults.TRUE, TestResults.PARTIALLY, TestResults.FALSE),
        FALSE_PARTIAL_TRUE_OTHER(TestResults.FALSE, TestResults.PARTIALLY, TestResults.TRUE);

        public final TestResults highestPriority;
        private final Map<TestResults, Integer> priorityMap = new EnumMap<>(TestResults.class);

        private MergeStrategy(TestResults... priority) {
            highestPriority = priority[0];
            for (int i = 0; i < priority.length; i++) {
                // first element has highest priority
                // last element has priority 1
                priorityMap.put(priority[i], priority.length - i);
            }
        }

        public int getPriority(TestResults result) {
            return priorityMap.getOrDefault(result, 0);
        }
    }

    private MergeStrategy strategy;

    public VersionDependentTestResult(MergeStrategy strategy) {
        this.strategy = strategy;
    }

    public void putResult(ProtocolVersion version, boolean result) {
        results.put(version, TestResults.of(result));
    }

    public TestResults getSummarizedResult() {
        TestResults highestResult = null;
        int highestResultPriority = -1;

        for (TestResults result : results.values()) {
            if (result == strategy.highestPriority) {
                return result;
            }

            int currentResultPriority = strategy.getPriority(result);
            if (currentResultPriority > highestResultPriority) {
                highestResult = result;
            }
        }
        return highestResult;
    }

    @Override
    public String getName() {
        return getSummarizedResult().getName();
    }
}
