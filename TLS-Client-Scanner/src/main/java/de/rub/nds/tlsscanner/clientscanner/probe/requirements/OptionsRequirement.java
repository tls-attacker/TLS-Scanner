package de.rub.nds.tlsscanner.clientscanner.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;

public class OptionsRequirement extends Requirement {

	private ClientScannerConfig scannerConfig;
	private String type;
	private String domain;

	public OptionsRequirement(ClientScannerConfig scannerConfig, String type) {
		super();
		this.scannerConfig = scannerConfig;
		this.type = type;
	}

	public OptionsRequirement(ClientScannerConfig scannerConfig, String type, String domain) {
		super();
		this.scannerConfig = scannerConfig;
		this.type = type;
		this.domain = domain;
	}

	@Override
	protected boolean evaluateIntern(ScanReport report) {
		if (scannerConfig == null || type == null) {
			return false;
		}
		if (type == "ALPN") {
			return scannerConfig.getClientParameterDelegate().getAlpnOptions() != null;
		}

		// TODO is this correct for null domains?
		if (type == "SNI") {
			if (domain != null) {
				return scannerConfig.getClientParameterDelegate().getSniOptions(domain) != null;
			} else {
				return false;
			}
		}
		if (type == "RESUMPTION") {
			return scannerConfig.getClientParameterDelegate().getResumptionOptions() != null;
		}
		return false;
	}

	public String getRequirement() {
		return type;
	}

	@Override
	public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
		if (evaluateIntern(report) == false) {
			return next.getMissingRequirementIntern(missing.requires(new OptionsRequirement(scannerConfig, type)),
					report);
		}
		return next.getMissingRequirementIntern(missing, report);
	}
}
