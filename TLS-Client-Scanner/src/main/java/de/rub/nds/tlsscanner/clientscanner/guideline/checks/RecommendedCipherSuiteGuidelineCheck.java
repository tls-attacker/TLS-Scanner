/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline.checks;

import de.rub.nds.scanner.core.guideline.*;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.clientscanner.guideline.results.RecommendedCipherSuiteGuidelineCheckResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RecommendedCipherSuiteGuidelineCheck extends GuidelineCheck<ClientReport> {

    /** The protocol versions this check applies to. */
    private List<ProtocolVersion> versions;

    private List<CipherSuite> cipherSuitesInQuestion;

    private RecommendedCipherSuiteGuidelineCheck() {
        super(null, null);
    }

    public RecommendedCipherSuiteGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            List<ProtocolVersion> versions,
            List<CipherSuite> cipherSuitesInQuestion) {
        super(name, requirementLevel);
        this.versions = versions;
        this.cipherSuitesInQuestion = cipherSuitesInQuestion;
    }

    public RecommendedCipherSuiteGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            List<ProtocolVersion> versions,
            List<CipherSuite> cipherSuitesInQuestion) {
        super(name, requirementLevel, condition);
        this.versions = versions;
        this.cipherSuitesInQuestion = cipherSuitesInQuestion;
    }

    @Override
    public boolean passesCondition(ClientReport report) {
        return this.versions.stream().anyMatch(report.getSupportedProtocolVersions()::contains)
                && super.passesCondition(report);
    }

    @Override
    public GuidelineCheckResult evaluate(ClientReport report) {
        Set<CipherSuite> supportedCipherSuites = new HashSet<>();
        List<CipherSuite> notRecommendedCipherSuites = null;
        for (VersionSuiteListPair pair : report.getVersionSuitePairs()) {
            if (versions.contains(pair.getVersion())) {
                supportedCipherSuites.addAll(pair.getCipherSuiteList());
            }
        }
        notRecommendedCipherSuites =
                supportedCipherSuites.stream()
                        .filter(suite -> !cipherSuitesInQuestion.contains(suite))
                        .collect(Collectors.toList());
        return new RecommendedCipherSuiteGuidelineCheckResult(
                getName(),
                GuidelineAdherence.of(notRecommendedCipherSuites.isEmpty()),
                notRecommendedCipherSuites);
    }

    @Override
    public String toString() {
        return "CipherSuite_"
                + getRequirementLevel()
                + "_"
                + versions
                + "_"
                + cipherSuitesInQuestion;
    }

    private List<CipherSuite> nonRecommendedSuites(ClientReport report) {
        Set<CipherSuite> supported = new HashSet<>();
        for (VersionSuiteListPair pair : report.getVersionSuitePairs()) {
            if (versions.contains(pair.getVersion())) {
                supported.addAll(pair.getCipherSuiteList());
            }
        }
        return supported.stream()
                .filter(suite -> !cipherSuitesInQuestion.contains(suite))
                .collect(Collectors.toList());
    }

    public List<ProtocolVersion> getVersions() {
        return versions;
    }

    public List<CipherSuite> getCipherSuitesInQuestion() {
        return cipherSuitesInQuestion;
    }
}
