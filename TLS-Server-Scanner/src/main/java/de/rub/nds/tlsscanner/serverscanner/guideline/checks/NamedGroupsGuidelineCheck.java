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
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.NamedGroupsGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class NamedGroupsGuidelineCheck extends GuidelineCheck<ServerReport> {

    /**
     * Only these are allowed.
     */
    private List<NamedGroup> recommendedGroups;
    /**
     * At least one of these has to be present.
     */
    private List<NamedGroup> requiredGroups;
    private boolean tls13;
    private int minGroupCount = 0;

    private NamedGroupsGuidelineCheck() {
        super(null, null);
    }

    public NamedGroupsGuidelineCheck(String name, RequirementLevel requirementLevel, List<NamedGroup> recommendedGroups,
        List<NamedGroup> requiredGroups, boolean tls13, int minGroupCount) {
        super(name, requirementLevel);
        this.recommendedGroups = recommendedGroups;
        this.requiredGroups = requiredGroups;
        this.tls13 = tls13;
        this.minGroupCount = minGroupCount;
    }

    public NamedGroupsGuidelineCheck(String name, RequirementLevel requirementLevel, GuidelineCheckCondition condition,
        List<NamedGroup> recommendedGroups, List<NamedGroup> requiredGroups, boolean tls13, int minGroupCount) {
        super(name, requirementLevel, condition);
        this.recommendedGroups = recommendedGroups;
        this.requiredGroups = requiredGroups;
        this.tls13 = tls13;
        this.minGroupCount = minGroupCount;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        List<NamedGroup> supportedGroups =
            this.tls13 ? report.getSupportedTls13Groups() : report.getSupportedNamedGroups();
        if (supportedGroups == null) {
            return new NamedGroupsGuidelineCheckResult(TestResults.UNCERTAIN);
        }
        if (requiredGroups != null && !requiredGroups.isEmpty()) {
            boolean found = false;
            for (NamedGroup group : supportedGroups) {
                if (this.requiredGroups.contains(group)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return new NamedGroupsGuidelineCheckResult(TestResults.FALSE, requiredGroups);
            }
        }
        if (supportedGroups.size() < minGroupCount) {
            return new NamedGroupsGuidelineCheckResult(TestResults.FALSE, supportedGroups.size());
        }
        Set<NamedGroup> nonRecommended = new HashSet<>();
        for (NamedGroup group : supportedGroups) {
            if (this.recommendedGroups != null && !this.recommendedGroups.contains(group)) {
                nonRecommended.add(group);
            }
        }
        if (nonRecommended.isEmpty()) {
            return new NamedGroupsGuidelineCheckResult(TestResults.TRUE);
        } else {
            return new NamedGroupsGuidelineCheckResult(TestResults.FALSE, nonRecommended);
        }
    }

    @Override
    public String getId() {
        return "NamedGroups_" + getRequirementLevel() + "_" + recommendedGroups + "_" + requiredGroups + "_" + tls13
            + "_" + minGroupCount;
    }

    public List<NamedGroup> getRequiredGroups() {
        return requiredGroups;
    }

    public int getMinGroupCount() {
        return minGroupCount;
    }

    public List<NamedGroup> getRecommendedGroups() {
        return recommendedGroups;
    }

    public boolean isTls13() {
        return tls13;
    }

}
