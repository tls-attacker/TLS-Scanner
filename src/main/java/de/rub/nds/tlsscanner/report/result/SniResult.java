package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;

public class SniResult extends ProbeResult {

    private Boolean requiresSni;
    
    public SniResult(Boolean requiresSni) {
        super(ProbeType.SNI);
        this.requiresSni = requiresSni; 
    }

    @Override
    public void merge(SiteReport report) {
        report.setRequiresSni(requiresSni);
    }

}
