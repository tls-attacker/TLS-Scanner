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
import org.apache.commons.lang3.tuple.Pair;

public class ExtensionGuidelineCheck extends ConditionalGuidelineCheck {

    private ExtensionType extension;

    @Override
    public Pair<GuidelineCheckStatus, String> evaluateStatus(SiteReport report) {
        return report.getSupportedExtensions().contains(extension)
            ? Pair.of(GuidelineCheckStatus.PASSED, "The server supports " + this.extension)
            : Pair.of(GuidelineCheckStatus.FAILED, "The server does not support " + this.extension);
    }

    public ExtensionType getExtension() {
        return extension;
    }

    public void setExtension(ExtensionType extension) {
        this.extension = extension;
    }
}
