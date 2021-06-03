/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.guideline.model.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.model.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.VersionSuiteListPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class GuidelineChecker {

    private final static Logger LOGGER = LoggerFactory.getLogger(GuidelineCheck.class);

    private final SiteReport report;

    public GuidelineChecker(SiteReport report) {
        this.report = report;
    }

    public List<CipherSuite> getDisallowedSuites(List<ProtocolVersion> versions, List<CipherSuite> cipherSuites) {
        Set<CipherSuite> supported = new HashSet<>();
        for (VersionSuiteListPair pair : report.getVersionSuitePairs()) {
            if (versions.contains(pair.getVersion())) {
                supported.addAll(pair.getCipherSuiteList());
            }
        }

        return supported.stream().filter(suite -> !cipherSuites.contains(suite)).collect(Collectors.toList());
    }

    public boolean supportsOneOf(List<ProtocolVersion> versions) {
        for (ProtocolVersion version : versions) {
            if (report.getVersions().contains(version)) {
                return true;
            }
        }
        return false;
    }

    public boolean passesCheck(GuidelineCheck check) {
        switch (check.getRequirementLevel()) {
            case MUST:
            case SHOULD:
                return check.getResult().equals(report.getResult(check.getAnalyzedProperty()));
            case MUST_NOT:
            case SHOULD_NOT:
                return !check.getResult().equals(report.getResult(check.getAnalyzedProperty()));
            case MAY:
                return true;
            default:
                throw new IllegalArgumentException("Unknown Requirement Level: " + check.getRequirementLevel());
        }
    }

    public boolean isTrue(GuidelineCheckCondition condition) {
        if (condition == null) {
            return true;
        }
        if (condition.getAnd() != null) {
            for (GuidelineCheckCondition andCondition : condition.getAnd()) {
                if (!this.isTrue(andCondition)) {
                    return false;
                }
            }
            return true;
        } else if (condition.getOr() != null) {
            for (GuidelineCheckCondition orCondition : condition.getOr()) {
                if (this.isTrue(orCondition)) {
                    return true;
                }
            }
            return false;
        } else if (condition.getAnalyzedProperty() != null && condition.getResult() != null) {
            return condition.getResult().equals(report.getResult(condition.getAnalyzedProperty()));
        }
        LOGGER.warn("Invalid condition object.");
        return false;
    }
}
