package de.rub.nds.tlsscanner.serverscanner.requirements;

import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;

public class TestTlsProbe extends TlsProbe{

	public TestTlsProbe(ParallelExecutor parallelExecutor, ProbeType type, ScannerConfig scannerConfig) {
		super(parallelExecutor, type, scannerConfig);
		// TODO Auto-generated constructor stub
	}

	@Override
	public ProbeResult executeTest() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean canBeExecuted(SiteReport report) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public ProbeResult getCouldNotExecuteResult() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void adjustConfig(SiteReport report) {
		// TODO Auto-generated method stub
		
	}

}
