/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.ExtensionGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class ExtensionGuidelineCheck extends GuidelineCheck {

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
    public GuidelineCheckResult evaluate(SiteReport report) {
        return new ExtensionGuidelineCheckResult(
            TestResult.of(report.getSupportedExtensions().contains(requiredExtension)), requiredExtension);
    }

    @Override
    public String getId() {
        return "Extension_" + getRequirementLevel() + "_" + requiredExtension;
    }

    public ExtensionType getRequiredExtension() {
        return requiredExtension;
    }

    public void setRequiredExtension(ExtensionType requiredExtension) {
        this.requiredExtension = requiredExtension;
    }

}
