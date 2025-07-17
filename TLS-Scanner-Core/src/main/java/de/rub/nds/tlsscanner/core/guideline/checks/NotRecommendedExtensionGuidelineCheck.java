/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.guideline.checks;

import de.rub.nds.scanner.core.guideline.*;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.guideline.results.NotRecommendedExtensionGuidelineCheckResult;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class NotRecommendedExtensionGuidelineCheck extends TlsGuidelineCheck {

    private List<ExtensionType> notRecommendedExtensions;

    private NotRecommendedExtensionGuidelineCheck() {
        super(null, null);
    }

    public NotRecommendedExtensionGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            ExtensionType... notRecommendedExtensions) {
        super(name, requirementLevel);
        this.notRecommendedExtensions = Arrays.asList(notRecommendedExtensions);
    }

    public NotRecommendedExtensionGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            ExtensionType... notRecommendedExtensions) {
        super(name, requirementLevel, condition);
        this.notRecommendedExtensions = Arrays.asList(notRecommendedExtensions);
    }

    @Override
    public GuidelineCheckResult evaluate(TlsScanReport report) {
        GuidelineAdherence adherence;
        List<ExtensionType> notRecommendedButSupportedExtensions =
                notRecommendedExtensions.stream()
                        .filter(report.getSupportedExtensions()::contains)
                        .collect(Collectors.toList());

        adherence = GuidelineAdherence.of(notRecommendedButSupportedExtensions.isEmpty());

        return new NotRecommendedExtensionGuidelineCheckResult(
                getName(), adherence, notRecommendedButSupportedExtensions);
    }

    @Override
    public String toString() {
        return "NotRecommendedExtension_" + getRequirementLevel() + "_" + notRecommendedExtensions;
    }

    public List<ExtensionType> getNotRecommendedExtensions() {
        return Collections.unmodifiableList(notRecommendedExtensions);
    }
}
