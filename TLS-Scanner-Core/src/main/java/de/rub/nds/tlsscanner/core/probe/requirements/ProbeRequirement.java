/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

public class ProbeRequirement extends Requirement {
	private final TlsProbeType[] probes;
	
	public ProbeRequirement(TlsProbeType... probes){
		super();
		this.probes = probes;
	}
	
	@Override
	public boolean evaluate(ScanReport report) {
		if (probes == null || probes.length == 0)
			return next.evaluate(report);
		for (TlsProbeType pt : probes) {
			if (report.isProbeAlreadyExecuted(pt) == false)
				return false;
		}
		return next.evaluate(report);
	}
	
	/**
	 * @return the required probes
	 */
	public TlsProbeType[] getRequirement() {
		return probes;
	}
}