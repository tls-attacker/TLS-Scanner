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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.ArrayList;
import java.util.List;

public class ProtocolRequirement extends Requirement {
	private final ProtocolVersion[] protocols;
	private List<ProtocolVersion> missing;

	public ProtocolRequirement(ProtocolVersion... protocols) {
		super();
		this.protocols = protocols;
		this.missing = new ArrayList<>();
	}

	@Override
	protected boolean evaluateIntern(ScanReport report) {
		if ((protocols == null) || (protocols.length == 0)) {
			return true;
		}
		boolean returnValue = false;
		missing = new ArrayList<>();
		List<ProtocolVersion> protocolVersions = ((TlsScanReport) report).getSupportedProtocolVersions();
		if (protocolVersions != null && !protocolVersions.isEmpty()) {
			for (ProtocolVersion protocol : protocols) {
				if (protocolVersions.contains(protocol)) {
					returnValue = true;
				} else {
					missing.add(protocol);
				}
			}
		} else {
			for (ProtocolVersion protocol : protocols) {
				missing.add(protocol);
			}
		}
		return returnValue;
	}

	public ProtocolVersion[] getRequirement() {
		return protocols;
	}

	@Override
	public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
		if (evaluateIntern(report) == false) {
			return next.getMissingRequirementIntern(
					missing.requires(
							new ProtocolRequirement(this.missing.toArray(new ProtocolVersion[this.missing.size()]))),
					report);
		}
		return next.getMissingRequirementIntern(missing, report);
	}
}
