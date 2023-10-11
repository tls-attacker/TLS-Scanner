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
import java.util.EnumMap;
import java.util.Map;

public class PriorityBasedTestResultsMerger implements TestResultsMerger {
    public static final PriorityBasedTestResultsMerger TRUE_PRIORITY =
            new PriorityBasedTestResultsMerger(
                    TestResults.TRUE, TestResults.PARTIALLY, TestResults.FALSE);
    public static final PriorityBasedTestResultsMerger FALSE_PRIORITY =
            new PriorityBasedTestResultsMerger(
                    TestResults.FALSE, TestResults.PARTIALLY, TestResults.TRUE);

    public final TestResults highestPriority;
    private final Map<TestResults, Integer> priorityMap = new EnumMap<>(TestResults.class);

    public PriorityBasedTestResultsMerger(TestResults... priority) {
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

    @Override
    public TestResults merge(Iterable<TestResults> results) {
        TestResults highestResult = null;
        int highestResultPriority = -1;

        for (TestResults result : results) {
            if (result == highestPriority) {
                return result;
            }

            int currentResultPriority = getPriority(result);
            if (currentResultPriority > highestResultPriority) {
                highestResult = result;
            }
        }
        if (highestResult == null) {
            return TestResults.UNASSIGNED_ERROR;
        }
        return highestResult;
    }
}
