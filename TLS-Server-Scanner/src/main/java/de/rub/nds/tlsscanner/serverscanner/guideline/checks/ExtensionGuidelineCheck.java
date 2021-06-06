/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.serverscanner.guideline.ConditionalGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.GuidelineCheckStatus;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class ExtensionGuidelineCheck extends ConditionalGuidelineCheck {

    private ExtensionType extension;

    @Override
    public GuidelineCheckStatus evaluateStatus(SiteReport report) {
        return report.getSupportedExtensions().contains(extension) ? GuidelineCheckStatus.PASSED
            : GuidelineCheckStatus.FAILED;
    }

    public ExtensionType getExtension() {
        return extension;
    }

    public void setExtension(ExtensionType extension) {
        this.extension = extension;
    }
}
