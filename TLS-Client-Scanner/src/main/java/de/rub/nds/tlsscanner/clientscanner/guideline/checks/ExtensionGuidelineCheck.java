/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline.checks;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.clientscanner.guideline.results.ExtensionGuidelineCheckResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ExtensionGuidelineCheck extends GuidelineCheck<ClientReport> {

    private List<ExtensionType> affectedExtensions;

    private ExtensionGuidelineCheck() {
        super(null, null);
    }

    public ExtensionGuidelineCheck(
            String name, RequirementLevel requirementLevel, ExtensionType ...affectedExtensions) {
        super(name, requirementLevel);
        this.affectedExtensions = Arrays.asList(affectedExtensions);
    }

    public ExtensionGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            ExtensionType ...affectedExtensions) {
        super(name, requirementLevel, condition);
        this.affectedExtensions = Arrays.asList(affectedExtensions);
    }

    @Override
    public GuidelineCheckResult evaluate(ClientReport report) {
        GuidelineAdherence adherence;
        List<ExtensionType> supportedExtensions = affectedExtensions.stream().filter(report.getSupportedExtensions()::contains).collect(Collectors.toList());

        if (getRequirementLevel() == RequirementLevel.MUST_NOT
                || getRequirementLevel() == RequirementLevel.SHOULD_NOT) {
            adherence =
                    GuidelineAdherence.of(supportedExtensions.isEmpty());
        } else if (getRequirementLevel() == RequirementLevel.MAY) {
            adherence = GuidelineAdherence.ADHERED;
        } else {
            adherence =
                    GuidelineAdherence.of(
                            supportedExtensions.size() == affectedExtensions.size());
        }

        return new ExtensionGuidelineCheckResult(
                getName(),
                adherence,
                supportedExtensions,
                affectedExtensions);
    }

    @Override
    public String toString() {
        return "Extension_" + getRequirementLevel() + "_" + affectedExtensions;
    }

    public List<ExtensionType> getAffectedExtensions() {
        return Collections.unmodifiableList(affectedExtensions);
    }
}
