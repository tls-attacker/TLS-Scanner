/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import com.google.common.base.Joiner;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public class NamedGroupsGuidelineCheckResult extends GuidelineCheckResult {

    private Set<NamedGroup> notRecommendedGroups;
    private List<NamedGroup> missingRequired;
    private Integer groupCount;

    public NamedGroupsGuidelineCheckResult(TestResult result) {
        super(result);
    }

    public NamedGroupsGuidelineCheckResult(TestResult result, Set<NamedGroup> notRecommendedGroups) {
        super(result);
        this.notRecommendedGroups = notRecommendedGroups;
    }

    public NamedGroupsGuidelineCheckResult(TestResult result, List<NamedGroup> missingRequired) {
        super(result);
        this.missingRequired = missingRequired;
    }

    public NamedGroupsGuidelineCheckResult(TestResult result, Integer groupCount) {
        super(result);
        this.groupCount = groupCount;
    }

    @Override
    public String display() {
        if (Objects.equals(TestResult.UNCERTAIN, getResult())) {
            return "Missing information.";
        }
        if (Objects.equals(TestResult.TRUE, getResult())) {
            return "Server passed the named groups check.";
        }
        if (notRecommendedGroups != null && !notRecommendedGroups.isEmpty()) {
            return "The following groups were supported but not recommended:\n"
                + Joiner.on('\n').join(notRecommendedGroups);
        }
        if (missingRequired != null && !missingRequired.isEmpty()) {
            return "Server is missing one of required groups::\n" + Joiner.on('\n').join(missingRequired);
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
