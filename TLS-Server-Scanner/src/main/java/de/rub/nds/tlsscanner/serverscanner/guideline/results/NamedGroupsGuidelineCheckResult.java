/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import com.google.common.base.Joiner;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class NamedGroupsGuidelineCheckResult extends GuidelineCheckResult {

    private Set<NamedGroup> notRecommendedGroups;
    private List<NamedGroup> missingRequired;
    private Integer groupCount;

    public NamedGroupsGuidelineCheckResult(String checkName, GuidelineAdherence adherence) {
        super(checkName, adherence);
    }

    public NamedGroupsGuidelineCheckResult(
            String checkName, GuidelineAdherence adherence, Set<NamedGroup> notRecommendedGroups) {
        super(checkName, adherence);
        this.notRecommendedGroups = notRecommendedGroups;
    }

    public NamedGroupsGuidelineCheckResult(
            String checkName, GuidelineAdherence adherence, List<NamedGroup> missingRequired) {
        super(checkName, adherence);
        this.missingRequired = missingRequired;
    }

    public NamedGroupsGuidelineCheckResult(
            String checkName, GuidelineAdherence adherence, Integer groupCount) {
        super(checkName, adherence);
        this.groupCount = groupCount;
    }

    @Override
    public String toString() {
        if (Objects.equals(GuidelineAdherence.CHECK_FAILED, getAdherence())) {
            return "Missing information.";
        }
        if (Objects.equals(GuidelineAdherence.ADHERED, getAdherence())) {
            return "Server passed the named groups check.";
        }
        if (notRecommendedGroups != null && !notRecommendedGroups.isEmpty()) {
            return "The following groups were supported but not recommended:\n"
                    + Joiner.on('\n').join(notRecommendedGroups);
        }
        if (missingRequired != null && !missingRequired.isEmpty()) {
            return "Server is missing one of required groups::\n"
                    + Joiner.on('\n').join(missingRequired);
        }
        if (groupCount != null) {
            return "Server only supports " + groupCount + " groups.";
        }
        return null;
    }

    public Set<NamedGroup> getNotRecommendedGroups() {
        return notRecommendedGroups;
    }

    public List<NamedGroup> getMissingRequired() {
        return missingRequired;
    }

    public Integer getGroupCount() {
        return groupCount;
    }
}
