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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;

/**
 * Represents a {@link Requirement} for required {@link TlsAnalyzedProperty} properties which were
 * negatively evaluated (TestResults.FALSE).
 */
public class PropertyNotRequirement extends Requirement {

    private final TlsAnalyzedProperty[] propertiesNot;
    private List<TlsAnalyzedProperty> missing;

    /**
     * @param propertiesNot the required negatively evaluated {@link TlsAnalyzedProperty}
     *     properties. Any amount possible.
     */
    public PropertyNotRequirement(TlsAnalyzedProperty... propertiesNot) {
        super();
        this.propertiesNot = propertiesNot;
        this.missing = new ArrayList<>();
    }

    @Override
    protected boolean evaluateIntern(ScanReport report) {
        if ((propertiesNot == null) || (propertiesNot.length == 0)) {
            return true;
        }
        boolean returnValue = true;
        missing = new ArrayList<>();
        Map<String, TestResult> propertyMap = report.getResultMap();
        for (TlsAnalyzedProperty property : propertiesNot) {
            if (propertyMap.containsKey(property.toString())) {
                if (propertyMap.get(property.toString()) != TestResults.FALSE) {
                    returnValue = false;
                    missing.add(property);
                }
            } else {
                returnValue = false;
                missing.add(property);
            }
        }
        return returnValue;
    }

    @Override
    public String toString() {
        String returnString = "";   
        if (propertiesNot.length==1) {
        	returnString+="Property not: ";

        }else {
        	returnString+="Properties not: ";
        }
        return returnString+=Arrays.stream(propertiesNot).map(TlsAnalyzedProperty::name).collect(Collectors.joining(", "));
    }

    /**
     * @return the required negatively evaluated {@link TlsAnalyzedProperty} properties.
     */
    public TlsAnalyzedProperty[] getRequirement() {
        return propertiesNot;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateIntern(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(
                            new PropertyNotRequirement(
                                    this.missing.toArray(
                                            new TlsAnalyzedProperty[this.missing.size()]))),
                    report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
