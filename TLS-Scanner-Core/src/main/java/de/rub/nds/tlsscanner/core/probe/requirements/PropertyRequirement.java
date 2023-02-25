/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import java.util.ArrayList;
import java.util.Map;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.BooleanRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;

/**
 * Represents a {@link Requirement} for required {@link TlsAnalyzedProperty} properties which were
 * positively evaluated (TestResults.TRUE).
 */
public class PropertyRequirement extends BooleanRequirement {
    /**
     * @param properties the required {@link TlsAnalyzedProperty} properties. Any amount possible.
     */
    public PropertyRequirement(TlsAnalyzedProperty... properties) {
        super(properties);
    }

    @Override
    protected boolean evaluateInternal(ScanReport report) {
        if ((parameters == null) || (parameters.length == 0)) {
            return true;
        }
        boolean returnValue = true;
        missingParameters = new ArrayList<>();
        Map<String, TestResult> propertyMap = report.getResultMap();
        for (Enum<?> property : parameters) {
            if (propertyMap.containsKey(property.toString())) {
                if (propertyMap.get(property.toString()) != TestResults.TRUE) {
                    returnValue = false;
                    missingParameters.add(property);
                }
            } else {
                returnValue = false;
                missingParameters.add(property);
            }
        }
        return returnValue;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateInternal(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(
                            new PropertyRequirement(
                                    this.missingParameters.toArray(
                                            new TlsAnalyzedProperty[this.missingParameters.size()]))),
                    report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
