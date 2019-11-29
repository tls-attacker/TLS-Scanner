package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;

public class RacoonAttackProbe extends TlsProbe {

    public RacoonAttackProbe(ParallelExecutor parallelExecutor, ScannerConfig scannerConfig) {
        super(parallelExecutor, ProbeType.RACOON_ATTACK, scannerConfig, 0);
    }

    @Override
    public ProbeResult executeTest() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (report.getResult(AnalyzedProperty.SUPPORTS_DH) == TestResult.TRUE) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void adjustConfig(SiteReport report) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
