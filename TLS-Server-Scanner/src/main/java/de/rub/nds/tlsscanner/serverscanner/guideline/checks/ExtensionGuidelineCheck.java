/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheck;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.ExtensionGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ExtensionGuidelineCheck extends GuidelineCheck<ServerReport> {

    private ExtensionType requiredExtension;

    private ExtensionGuidelineCheck() {
        super(null, null);
    }

    public ExtensionGuidelineCheck(
            String name, RequirementLevel requirementLevel, ExtensionType requiredExtension) {
        super(name, requirementLevel);
        this.requiredExtension = requiredExtension;
    }

    public ExtensionGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            ExtensionType requiredExtension) {
        super(name, requirementLevel, condition);
        this.requiredExtension = requiredExtension;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        return new ExtensionGuidelineCheckResult(
                getName(),
                GuidelineAdherence.of(report.getSupportedExtensions().contains(requiredExtension)),
                report.getSupportedExtensions().contains(requiredExtension),
                requiredExtension);
    }

    @Override
    public String toString() {
        return "Extension_" + getRequirementLevel() + "_" + requiredExtension;
    }

    public ExtensionType getRequiredExtension() {
        return requiredExtension;
    }
}
