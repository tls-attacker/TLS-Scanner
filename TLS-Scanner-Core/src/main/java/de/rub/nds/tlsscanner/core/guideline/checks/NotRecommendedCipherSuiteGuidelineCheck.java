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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.guideline.results.NotRecommendedCipherSuiteGuidelineCheckResult;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class NotRecommendedCipherSuiteGuidelineCheck extends TlsGuidelineCheck {

    /** The protocol versions this check applies to. */
    private List<ProtocolVersion> versions;

    private List<CipherSuite> notRecommendedCipherSuites;

    private NotRecommendedCipherSuiteGuidelineCheck() {
        super(null, null);
    }

    public NotRecommendedCipherSuiteGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<ProtocolVersion> versions,
            List<CipherSuite> notRecommendedCipherSuites) {
        super(name, requirementLevel);
        this.versions = versions;
        this.notRecommendedCipherSuites = notRecommendedCipherSuites;
    }

    public NotRecommendedCipherSuiteGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<ProtocolVersion> versions,
            List<CipherSuite> notRecommendedCipherSuites) {
        super(name, requirementLevel, condition);
        this.versions = versions;
        this.notRecommendedCipherSuites = notRecommendedCipherSuites;
    }

    @Override
    public boolean passesCondition(TlsScanReport report) {
        return report.getSupportedProtocolVersions() != null
                && this.versions.stream().anyMatch(report.getSupportedProtocolVersions()::contains)
                && super.passesCondition(report);
    }

    @Override
    public GuidelineCheckResult evaluate(TlsScanReport report) {
        Set<CipherSuite> supportedCipherSuites = new HashSet<>();
        List<CipherSuite> notRecommendedButSupportedCipherSuites = null;
        for (VersionSuiteListPair pair : report.getVersionSuitePairs()) {
            if (versions.contains(pair.getVersion())) {
                supportedCipherSuites.addAll(pair.getCipherSuiteList());
            }
        }

        notRecommendedButSupportedCipherSuites =
                supportedCipherSuites.stream()
                        .filter(suite -> this.notRecommendedCipherSuites.contains(suite))
                        .collect(Collectors.toList());
        return new NotRecommendedCipherSuiteGuidelineCheckResult(
                this,
                GuidelineAdherence.of(notRecommendedButSupportedCipherSuites.isEmpty()),
                notRecommendedButSupportedCipherSuites);
    }

    @Override
    public String toString() {
        return "NotRecommendedCipherSuite_"
                + getRequirementLevel()
                + "_"
                + versions
                + "_"
                + notRecommendedCipherSuites;
    }

    public List<ProtocolVersion> getVersions() {
        return versions;
    }

    public List<CipherSuite> getNotRecommendedCipherSuites() {
        return notRecommendedCipherSuites;
    }
}
