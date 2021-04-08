/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class RecordFragmentationResult extends ProbeResult {
    private Boolean supported = null;

    public RecordFragmentationResult(Boolean supported) {
        super(ProbeType.RECORD_FRAGMENTATION);

        this.supported = supported;
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.setSupportsRecordFragmentation(supported);
        report.putResult(AnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION, supported);
    }

    public Boolean getSupported() {
        return supported;
    }

    public void setSupported(Boolean supported) {
        this.supported = supported;
    }
}
