/*
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsscanner.probe.stats.ExtractedValueContainer;
import de.rub.nds.tlsscanner.probe.stats.TrackableValueType;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

public class EcPublicKeyAfterProbe extends AfterProbe {

    @Override
    public void analyze(SiteReport report) {
        List<ExtractedValueContainer> extractedValueContainerList = report.getExtractedValueContainerList();
        Boolean reuse = false;
        for (ExtractedValueContainer container : extractedValueContainerList) {
            if (container.getType() == TrackableValueType.ECDHE_PUBKEY) {
                if (!container.areAllValuesDiffernt()) {
                    reuse = true;
                    break;
                }
            }

        }
        report.setEcPubkeyReuse(reuse);
    }

}
