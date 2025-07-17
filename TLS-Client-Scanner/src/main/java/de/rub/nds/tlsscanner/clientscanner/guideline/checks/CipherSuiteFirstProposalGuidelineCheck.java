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
import de.rub.nds.tlsscanner.clientscanner.guideline.results.CipherSuiteFirstProposalGuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.checks.TlsGuidelineCheck;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * Checks if the first cipher suite proposed by the client for TLS 1.2 equals
 * TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 as recommended by RFC 9325.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CipherSuiteFirstProposalGuidelineCheck extends TlsGuidelineCheck {

    private CipherSuiteFirstProposalGuidelineCheck() {
        super(null, null);
    }

    public CipherSuiteFirstProposalGuidelineCheck(String name, RequirementLevel requirementLevel) {
        super(name, requirementLevel);
    }

    public CipherSuiteFirstProposalGuidelineCheck(
            String name, RequirementLevel requirementLevel, GuidelineCheckCondition condition) {
        super(name, requirementLevel, condition);
    }

    @Override
    public GuidelineCheckResult evaluate(TlsScanReport clientReport) {
        // Abort if TLS 1.2 is not supported by the client.
        if (!clientReport.getSupportedProtocolVersions().contains(ProtocolVersion.TLS12)) {
            return new CipherSuiteFirstProposalGuidelineCheckResult(
                    getName(), GuidelineAdherence.CONDITION_NOT_MET);
        }
        for (VersionSuiteListPair pair : clientReport.getVersionSuitePairs()) {
            if (pair.getVersion().equals(ProtocolVersion.TLS12)) {
                // Check if first proposed cipher suite for TLS 1.2 is the correct one.
                if (pair.getCipherSuiteList()
                        .getFirst()
                        .equals(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)) {
                    return new CipherSuiteFirstProposalGuidelineCheckResult(
                            getName(), GuidelineAdherence.ADHERED);
                }
            }
        }

        // If TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 is not the first cipher suite for TLS 1.2, the
        // check is violated.
        return new CipherSuiteFirstProposalGuidelineCheckResult(
                getName(), GuidelineAdherence.VIOLATED);
    }

    @Override
    public String toString() {
        return "CipherSuiteFirstProposalGuidelineCheck_" + getRequirementLevel();
    }
}
