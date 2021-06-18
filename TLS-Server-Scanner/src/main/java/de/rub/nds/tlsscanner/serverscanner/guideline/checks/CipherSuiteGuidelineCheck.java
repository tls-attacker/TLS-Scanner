/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import com.google.common.base.Joiner;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class CipherSuiteGuidelineCheck extends GuidelineCheck {

    private List<ProtocolVersion> versions;
    private List<CipherSuite> cipherSuites;

    @Override
    public Pair<GuidelineCheckStatus, String> evaluateStatus(SiteReport report) {
        List<CipherSuite> nonRecommended = this.nonRecommendedSuites(report);
        if (nonRecommended.isEmpty()) {
            return Pair.of(GuidelineCheckStatus.PASSED, "Only listed Cipher Suites are supported.");
        }
        return Pair.of(GuidelineCheckStatus.FAILED,
            "The following Cipher Suites were supported but not recommended:\n" + Joiner.on('\n').join(nonRecommended));
    }

    private List<CipherSuite> nonRecommendedSuites(SiteReport report) {
        Set<CipherSuite> supported = new HashSet<>();
        for (VersionSuiteListPair pair : report.getVersionSuitePairs()) {
            if (versions.contains(pair.getVersion())) {
                supported.addAll(pair.getCipherSuiteList());
            }
        }
        return supported.stream().filter(suite -> !cipherSuites.contains(suite)).collect(Collectors.toList());
    }

    public List<ProtocolVersion> getVersions() {
        return versions;
    }

    public void setVersions(List<ProtocolVersion> versions) {
        this.versions = versions;
    }

    public List<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(List<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }
}
