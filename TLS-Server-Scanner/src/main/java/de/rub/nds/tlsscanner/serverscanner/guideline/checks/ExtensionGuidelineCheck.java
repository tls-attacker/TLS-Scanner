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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ExtensionGuidelineCheck extends GuidelineCheck<ServerReport> {

    private List<ExtensionType> extensionsInQuestion;
    private boolean required; // If false this class checks if the provided extension is NOT set.

    private ExtensionGuidelineCheck() {
        super(null, null);
    }

    public ExtensionGuidelineCheck(
            String name, RequirementLevel requirementLevel, ExtensionType... extensionsInQuestion) {
        super(name, requirementLevel);
        this.extensionsInQuestion = Arrays.asList(extensionsInQuestion);
    }

    public ExtensionGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            ExtensionType... extensionsInQuestion) {
        super(name, requirementLevel, condition);
        this.extensionsInQuestion = Arrays.asList(extensionsInQuestion);
        this.required =
                true; // Default case, this means the extensionsInQuestion is expected to be
        // supported.
    }

    public ExtensionGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean required, // "Optional" parameter to invert the check this class performs.
            ExtensionType... extensionsInQuestion) {
        super(name, requirementLevel, condition);
        this.extensionsInQuestion = Arrays.asList(extensionsInQuestion);
        this.required = required;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        GuidelineAdherence adherence;
        List<ExtensionType> supportedExtensions =
                extensionsInQuestion.stream()
                        .filter(report.getSupportedExtensions()::contains)
                        .collect(Collectors.toList());

        if (!required) {
            adherence = GuidelineAdherence.of(supportedExtensions.isEmpty());
        } else {
            adherence =
                    GuidelineAdherence.of(
                            supportedExtensions.size() == extensionsInQuestion.size());
        }

        return new ExtensionGuidelineCheckResult(
                getName(), adherence, supportedExtensions, extensionsInQuestion);
    }

    @Override
    public String toString() {
        return "Extension_"
                + getRequirementLevel()
                + "_"
                + extensionsInQuestion
                + "_required_"
                + required;
    }

    public List<ExtensionType> getExtensionsInQuestion() {
        return Collections.unmodifiableList(extensionsInQuestion);
    }
}
