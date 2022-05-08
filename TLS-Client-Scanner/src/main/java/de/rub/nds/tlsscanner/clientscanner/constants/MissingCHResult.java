package de.rub.nds.tlsscanner.clientscanner.constants;

import de.rub.nds.scanner.core.constants.TestResult;

public class MissingCHResult implements TestResult{

	@Override
	public String name() {
		return "Could not test due to missing Client Hello!";
	}
}
