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
import de.rub.nds.tlsscanner.serverscanner.guideline.results.RequiredNamedGroupsGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RequiredNamedGroupsGuidelineCheck extends GuidelineCheck<ServerReport> {

    private List<NamedGroup> requiredGroups;
    private boolean onlyOneIsRequired;

    private RequiredNamedGroupsGuidelineCheck() {
        super(null, null);
    }

    public RequiredNamedGroupsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<NamedGroup> requiredGroups,
            boolean onlyOneIsRequired) {
        super(name, requirementLevel);
        this.requiredGroups = requiredGroups;
        this.onlyOneIsRequired = onlyOneIsRequired;
    }

    public RequiredNamedGroupsGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<NamedGroup> requiredGroups,
            boolean onlyOneIsRequired) {
        super(name, requirementLevel, condition);
        this.requiredGroups = requiredGroups;
        this.onlyOneIsRequired = onlyOneIsRequired;
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

        List<NamedGroup> requiredButNotSupported =
                requiredGroups.stream().filter(ng -> !supportedGroups.contains(ng)).toList();

        return new RequiredNamedGroupsGuidelineCheckResult(
                getName(),
                GuidelineAdherence.of(
                        (onlyOneIsRequired
                                        && requiredButNotSupported.size() < requiredGroups.size())
                                || requiredButNotSupported.isEmpty()),
                requiredButNotSupported,
                onlyOneIsRequired);
    }

    @Override
    public String toString() {
        return "RequiredNamedGroups_" + getRequirementLevel() + "_" + requiredGroups;
    }

    public List<NamedGroup> getRequiredGroups() {
        return requiredGroups;
    }
}
