package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;

public class NotRequirement extends Requirement{
	private final Requirement notRequirement;
	
	public NotRequirement(Requirement next, Requirement notRequirement){
		super();
		this.notRequirement = notRequirement;
		this.next = next;
	}
	
	public NotRequirement(Requirement notRequirement){
		super();
		this.notRequirement = notRequirement;
	}
	
	@Override
	public boolean evaluate(ScanReport report) {
		if (notRequirement == null)
			return next.evaluate(report);
		return !notRequirement.evaluate(report) && next.evaluate(report);
	}
	
	/**
	 * @return the not requirement
	 */
	public Requirement getRequirement() {
		return notRequirement;
	}
}
