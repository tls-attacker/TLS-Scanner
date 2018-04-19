package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.MacCheckPattern;
import de.rub.nds.tlsscanner.report.SiteReport;

public class MacResult extends ProbeResult {
    
    private final MacCheckPattern appDataPattern;
    private final MacCheckPattern finishedPattern;
    
    public MacResult(MacCheckPattern appDataPattern, MacCheckPattern finishedPattern) {
        super(ProbeType.MAC);
        this.appDataPattern = appDataPattern;
        this.finishedPattern = finishedPattern;
    }
    
    @Override
    public void merge(SiteReport report) {
        report.setMacCheckPatterAppData(appDataPattern);
        report.setMacCheckPatternFinished(finishedPattern);
    }
    
}
