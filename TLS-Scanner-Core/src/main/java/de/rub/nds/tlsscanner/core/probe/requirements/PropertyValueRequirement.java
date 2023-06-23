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

/**
 * Represents a {@link Requirement} for required {@link TlsAnalyzedProperty} properties which
 * evaluated to the expected values.
 */
public class PropertyValueRequirement<R extends TlsScanReport<R>>
        extends PrimitiveRequirement<R, TlsAnalyzedProperty> {

    private final TestResult requiredTestResult;

    public PropertyValueRequirement(
            TestResult requiredTestResult, List<TlsAnalyzedProperty> properties) {
        super(properties);
        this.requiredTestResult = requiredTestResult;
    }

    public PropertyValueRequirement(
            TestResult requiredTestResult, TlsAnalyzedProperty... properties) {
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
                    || propertyMap.get(property.toString()) == null
                    || !propertyMap.get(property.toString()).equals(requiredTestResult)) {
                checkPropertyValuePair(
                        property.toString(),
                        propertyMap.get(property.toString()),
                        requiredTestResult);
                return false;
            }
        }
        return true;
    }

    public TestResult getRequiredTestResult() {
        return requiredTestResult;
    }

    private void checkPropertyValuePair(
            String propertyString, TestResult listedResult, TestResult expectedResult) {
        if (listedResult != null && listedResult.getClass() != expectedResult.getClass()) {
            throw new IllegalArgumentException(
                    String.format(
                            "Requirement set for property %s expects wrong type of result (found %s but expected %s)",
                            propertyString, listedResult.getClass(), expectedResult.getClass()));
        }
    }

    @Override
    public String toString() {
        return String.format(
                "PropertyValueRequirement[%s: %s]",
                requiredTestResult,
                parameters.stream().map(Object::toString).collect(Collectors.joining(" ")));
    }
}
