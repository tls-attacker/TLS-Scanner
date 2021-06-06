/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

import java.util.List;

public class NamedGroupsGuidelineCheck extends GuidelineCheck {

    private List<NamedGroup> groups;
    private boolean tls13;

    @Override
    public GuidelineCheckStatus evaluateStatus(SiteReport report) {
        return this.supportsNonRecommendedGroup(report) ? GuidelineCheckStatus.FAILED : GuidelineCheckStatus.PASSED;
    }

    private boolean supportsNonRecommendedGroup(SiteReport report) {
        List<NamedGroup> supportedGroups =
            this.tls13 ? report.getSupportedTls13Groups() : report.getSupportedNamedGroups();
        return supportedGroups.stream().anyMatch(suite -> !this.groups.contains(suite));
    }

    public List<NamedGroup> getGroups() {
        return groups;
    }

    public void setGroups(List<NamedGroup> groups) {
        this.groups = groups;
    }

    public boolean isTls13() {
        return tls13;
    }

    public void setTls13(boolean tls13) {
        this.tls13 = tls13;
    }
}
