/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a {@link Requirement} for required ExtensionTypes.
 */
public class ExtensionRequirement extends Requirement {
	private final ExtensionType[] extensions;
	private List<ExtensionType> missing;

	/**
	 * @param extensions the required ExtensionTypes. Any amount possible.
	 */
	public ExtensionRequirement(ExtensionType... extensions) {
		super();
		this.extensions = extensions;
		this.missing = new ArrayList<>();
	}

	@Override
	protected boolean evaluateIntern(ScanReport report) {
		if ((extensions == null) || (extensions.length == 0)) {
			return true;
		}
		boolean returnValue = false;
		missing = new ArrayList<>();
		List<ExtensionType> extensionList = ((TlsScanReport) report).getSupportedExtensions();
		if (extensionList != null && !extensionList.isEmpty()) {
			for (ExtensionType extension : extensions) {
				if (extensionList.contains(extension)) {
					returnValue = true;
				} else {
					missing.add(extension);
				}
			}
		} else {
			for (ExtensionType extension : extensions) {
				missing.add(extension);
			}
		}
		return returnValue;
	}

	/**
	 * @return the ExtensionTypes.
	 */
	public ExtensionType[] getRequirement() {
		return extensions;
	}

	@Override
	public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
		if (evaluateIntern(report) == false) {
			return next.getMissingRequirementIntern(
					missing.requires(
							new ExtensionRequirement(this.missing.toArray(new ExtensionType[this.missing.size()]))),
					report);
		}
		return next.getMissingRequirementIntern(missing, report);
	}
}
