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
