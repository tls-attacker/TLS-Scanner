/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.guideline.*;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.RequiredExtensionGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RequiredExtensionGuidelineCheck extends GuidelineCheck<ServerReport> {

    private List<ExtensionType> requiredExtensions;

    private RequiredExtensionGuidelineCheck() {
        super(null, null);
    }

    public RequiredExtensionGuidelineCheck(
            String name, RequirementLevel requirementLevel, ExtensionType... requiredExtensions) {
        super(name, requirementLevel);
        this.requiredExtensions = Arrays.asList(requiredExtensions);
    }

    public RequiredExtensionGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            ExtensionType... requiredExtensions) {
        super(name, requirementLevel, condition);
        this.requiredExtensions = Arrays.asList(requiredExtensions);
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        GuidelineAdherence adherence;
        List<ExtensionType> requiredButNotSupported =
                requiredExtensions.stream()
                        .filter(ext -> !report.getSupportedExtensions().contains(ext))
                        .toList();

        adherence = GuidelineAdherence.of(requiredButNotSupported.isEmpty());

        return new RequiredExtensionGuidelineCheckResult(
                getName(), adherence, requiredButNotSupported);
    }

    @Override
    public String toString() {
        return "RequiredExtension_" + getRequirementLevel() + "_" + requiredExtensions;
    }

    public List<ExtensionType> getRequiredExtensions() {
        return Collections.unmodifiableList(requiredExtensions);
    }
}
