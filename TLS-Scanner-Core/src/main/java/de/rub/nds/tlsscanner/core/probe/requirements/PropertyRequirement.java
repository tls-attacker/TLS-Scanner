/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.requirements.PrimitiveRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Represents a {@link Requirement} for required {@link TlsAnalyzedProperty} properties. */
public class PropertyRequirement<R extends TlsScanReport<R>>
        extends PrimitiveRequirement<R, TlsAnalyzedProperty> {

    private final TestResult requiredTestResult;

    public PropertyRequirement(
            TestResult requiredTestResult, List<TlsAnalyzedProperty> properties) {
        super(properties);
        this.requiredTestResult = requiredTestResult;
    }

    public PropertyRequirement(TestResult requiredTestResult, TlsAnalyzedProperty... properties) {
        super(List.of(properties));
        this.requiredTestResult = requiredTestResult;
    }

    @Override
    public boolean evaluate(R report) {
        if (parameters.size() == 0) {
            return true;
        }
        Map<String, TestResult> propertyMap = report.getResultMap();
        for (TlsAnalyzedProperty property : parameters) {
            if (!propertyMap.containsKey(property.toString())
                    || propertyMap.get(property.toString()) != requiredTestResult) {
                return false;
            }
        }
        return true;
    }

    public TestResult getRequiredTestResult() {
        return requiredTestResult;
    }

    @Override
    public String toString() {
        return String.format(
                "PropertyRequirement[%s: %s]",
                requiredTestResult,
                parameters.stream().map(Object::toString).collect(Collectors.joining(" ")));
    }
}
