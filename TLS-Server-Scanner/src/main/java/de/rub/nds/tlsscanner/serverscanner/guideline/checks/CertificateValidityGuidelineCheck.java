/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsscanner.serverscanner.guideline.CertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import org.apache.commons.lang3.tuple.Pair;

import java.time.Duration;
import java.time.Instant;

public class CertificateValidityGuidelineCheck extends CertificateGuidelineCheck {

    private int years;

    @Override
    public Pair<GuidelineCheckStatus, String> evaluateChain(CertificateChain chain) {
        CertificateReport report = chain.getCertificateReportList().get(0);
        Duration validityPeriod = Duration.between(Instant.ofEpochMilli(report.getValidFrom().getTime()),
            Instant.ofEpochMilli(report.getValidTo().getTime()));

        if (validityPeriod.toDays() > this.years * 365L) {
            return Pair.of(GuidelineCheckStatus.FAILED, "Certificate is valid for too long.");
        }
        return Pair.of(GuidelineCheckStatus.PASSED, "Certificate Validity is okay.");
    }

    public int getYears() {
        return years;
    }

    public void setYears(int years) {
        this.years = years;
    }
}
