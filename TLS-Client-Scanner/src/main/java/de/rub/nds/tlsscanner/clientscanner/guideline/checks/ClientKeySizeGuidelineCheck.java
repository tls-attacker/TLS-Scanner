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
import de.rub.nds.tlsscanner.core.guideline.checks.TlsGuidelineCheck;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ClientKeySizeGuidelineCheck extends TlsGuidelineCheck {

    private Integer minimumDsaKeyLength;
    private Integer minimumRsaKeyLength;
    private Integer minimumEcKeyLength;
    private Integer minimumDhKeyLength;

    private ClientKeySizeGuidelineCheck() {
        super(null, null);
    }

    public ClientKeySizeGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            Integer minimumDsaKeyLength,
            Integer minimumRsaKeyLength,
            Integer minimumEcKeyLength,
            Integer minimumDhKeyLength) {
        super(name, requirementLevel);
        this.minimumDsaKeyLength = minimumDsaKeyLength;
        this.minimumRsaKeyLength = minimumRsaKeyLength;
        this.minimumEcKeyLength = minimumEcKeyLength;
        this.minimumDhKeyLength = minimumDhKeyLength;
    }

    public ClientKeySizeGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            Integer minimumDsaKeyLength,
            Integer minimumRsaKeyLength,
            Integer minimumEcKeyLength,
            Integer minimumDhKeyLength) {
        super(name, requirementLevel, condition);
        this.minimumDsaKeyLength = minimumDsaKeyLength;
        this.minimumRsaKeyLength = minimumRsaKeyLength;
        this.minimumEcKeyLength = minimumEcKeyLength;
        this.minimumDhKeyLength = minimumDhKeyLength;
    }

    @Override
    public GuidelineCheckResult evaluate(TlsScanReport report) {
        // TODO implement when ServerCertificateKeySizeProbe is reimplemented
        return new FailedCheckGuidelineResult(
                this, GuidelineAdherence.CHECK_FAILED, "Not implemented yet.");
    }
}
