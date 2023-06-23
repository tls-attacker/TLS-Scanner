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
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.PrimitiveRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Represents a {@link Requirement} for evaluated {@link TlsAnalyzedProperty} properties. */
public class PropertyRequirement<R extends TlsScanReport<R>>
        extends PrimitiveRequirement<R, TlsAnalyzedProperty> {

    public PropertyRequirement(List<TlsAnalyzedProperty> properties) {
        super(properties);
    }

    public PropertyRequirement(TlsAnalyzedProperty... properties) {
        super(Arrays.asList(properties));
    }

    @Override
    public boolean evaluate(R report) {
        if (parameters.size() == 0) {
            return true;
        }
        Map<String, TestResult> propertyMap = report.getResultMap();
        for (TlsAnalyzedProperty property : parameters) {
            if (!propertyMap.containsKey(property.toString())
                    || propertyMap.get(property.toString()) == TestResults.UNASSIGNED_ERROR) {
                return false;
            }
        }
        return true;
    }

    @Override
    public String toString() {
        return String.format(
                "PropertyRequirement[%s]",
                parameters.stream().map(Object::toString).collect(Collectors.joining(" ")));
    }
}
