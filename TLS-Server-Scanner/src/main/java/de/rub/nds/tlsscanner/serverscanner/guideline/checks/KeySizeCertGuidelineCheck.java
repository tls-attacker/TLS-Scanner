/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 * <p>
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.tlsscanner.serverscanner.guideline.CertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Locale;

public class KeySizeCertGuidelineCheck extends CertificateGuidelineCheck {

    private Integer dsa;
    private Integer rsa;
    private Integer ec;
    private Integer dh;

    @Override
    public Pair<GuidelineCheckStatus, String> evaluateStatus(SiteReport report) {
        if (report.getWeakestDhStrength() != null && this.dh != null) {
            if (report.getWeakestDhStrength() < this.dh) {
                return Pair.of(GuidelineCheckStatus.FAILED, String.format("Weakest DH size %d<%d", report.getWeakestDhStrength(), this.dh));
            }
        }
        return super.evaluateStatus(report);
    }

    @Override
    public Pair<GuidelineCheckStatus, String> evaluateChain(CertificateChain chain) {
        StringBuilder sb = new StringBuilder();
        int passCount = 0;
        int uncertainCount = 0;
        int failedCount = 0;
        for (CertificateReport report : chain.getCertificateReportList()) {
            if (!(report.getPublicKey() instanceof CustomPublicKey)) {
                uncertainCount++;
                continue;
            }
            CustomPublicKey key = (CustomPublicKey) report.getPublicKey();
            sb.append(report.getPublicKey().getAlgorithm()).append(" Key Size: ").append(key.keySize());
            switch (report.getPublicKey().getAlgorithm().toUpperCase(Locale.ENGLISH)) {
                case "DSA":
                    if (this.dsa != null && key.keySize() < this.dsa) {
                        sb.append('<').append(this.dsa).append('\n');
                        failedCount++;
                    } else {
                        sb.append('≥').append(this.dsa).append('\n');
                        passCount++;
                    }
                    break;
                case "RSA":
                    if (this.rsa != null && key.keySize() < this.rsa) {
                        sb.append('<').append(this.rsa).append('\n');
                        failedCount++;
                    } else {
                        sb.append('≥').append(this.rsa).append('\n');
                        passCount++;
                    }
                    break;
                case "EC":
                    if (this.ec != null && key.keySize() < this.ec) {
                        sb.append('<').append(this.ec).append('\n');
                        failedCount++;
                    } else {
                        sb.append('≥').append(this.ec).append('\n');
                        passCount++;
                    }
                    break;
                case "DH":
                    if (this.dh != null && key.keySize() < this.dh) {
                        sb.append('<').append(this.dh).append('\n');
                        failedCount++;
                    } else {
                        sb.append('≥').append(this.dh).append('\n');
                        passCount++;
                    }
                    break;
            }
        }
        if (failedCount > 0) {
            return Pair.of(GuidelineCheckStatus.FAILED, sb.toString());
        }
        if (uncertainCount > 0 || passCount == 0) {
            return Pair.of(GuidelineCheckStatus.UNCERTAIN, sb.toString());
        }
        return Pair.of(GuidelineCheckStatus.PASSED, sb.toString());
    }

    public Integer getDsa() {
        return dsa;
    }

    public void setDsa(Integer dsa) {
        this.dsa = dsa;
    }

    public Integer getRsa() {
        return rsa;
    }

    public void setRsa(Integer rsa) {
        this.rsa = rsa;
    }

    public Integer getEc() {
        return ec;
    }

    public void setEc(Integer ec) {
        this.ec = ec;
    }

    public Integer getDh() {
        return dh;
    }

    public void setDh(Integer dh) {
        this.dh = dh;
    }
}
