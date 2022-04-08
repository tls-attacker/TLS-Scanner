/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.ExtensionGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ExtensionGuidelineCheck extends GuidelineCheck<ServerReport> {

    private ExtensionType requiredExtension;

    private ExtensionGuidelineCheck() {
        super(null, null);
    }

    public ExtensionGuidelineCheck(String name, RequirementLevel requirementLevel, ExtensionType requiredExtension) {
        super(name, requirementLevel);
        this.requiredExtension = requiredExtension;
    }

    public ExtensionGuidelineCheck(String name, RequirementLevel requirementLevel, GuidelineCheckCondition condition,
        ExtensionType requiredExtension) {
        super(name, requirementLevel, condition);
        this.requiredExtension = requiredExtension;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        return new ExtensionGuidelineCheckResult(
            TestResults.of(report.getSupportedExtensions().contains(requiredExtension)),
            report.getSupportedExtensions().contains(requiredExtension), requiredExtension);
    }

    @Override
    public String getId() {
        return "Extension_" + getRequirementLevel() + "_" + requiredExtension;
    }

    public ExtensionType getRequiredExtension() {
        return requiredExtension;
    }
}
