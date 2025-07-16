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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.RecommendedNamedGroupsGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RecommendedNamedGroupsGuidelineCheck extends GuidelineCheck<ServerReport> {

    /** Only these are allowed. */
    private List<NamedGroup> recommendedGroups;

    private RecommendedNamedGroupsGuidelineCheck() {
        super(null, null);
    }

    public RecommendedNamedGroupsGuidelineCheck(
            String name, RequirementLevel requirementLevel, List<NamedGroup> recommendedGroups) {
        super(name, requirementLevel);
        this.recommendedGroups = recommendedGroups;
    }

    public RecommendedNamedGroupsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<NamedGroup> recommendedGroups) {
        super(name, requirementLevel, condition);
        this.recommendedGroups = recommendedGroups;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        Set<NamedGroup> supportedGroups = new HashSet<>();
        if (report.getSupportedTls13Groups() != null) {
            supportedGroups.addAll(report.getSupportedTls13Groups());
        }
        if (report.getSupportedNamedGroups() != null) {
            supportedGroups.addAll(report.getSupportedNamedGroups());
        }

        Set<NamedGroup> notRecommendedButSupported = new HashSet<>();
        for (NamedGroup group : supportedGroups) {
            if (recommendedGroups != null && !recommendedGroups.contains(group)) {
                notRecommendedButSupported.add(group);
            }
        }
        return new RecommendedNamedGroupsGuidelineCheckResult(
                getName(),
                GuidelineAdherence.of(notRecommendedButSupported.isEmpty()),
                notRecommendedButSupported);
    }

    @Override
    public String toString() {
        return "RecommendedNamedGroups_" + getRequirementLevel() + "_" + recommendedGroups;
    }

    public List<NamedGroup> getRecommendedGroups() {
        return recommendedGroups;
    }
}
