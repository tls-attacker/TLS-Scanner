/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class PropertyNotRequirement extends Requirement {

    private final TlsAnalyzedProperty[] propertiesNot;
    private List<TlsAnalyzedProperty> missing;

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

    public TlsAnalyzedProperty[] getRequirement() {
        return propertiesNot;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateIntern(report) == false) {
            return next.getMissingRequirementIntern(
                missing.requires(
                    new PropertyNotRequirement(this.missing.toArray(new TlsAnalyzedProperty[this.missing.size()]))),
                report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
