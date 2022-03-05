/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package requirements;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;

public class ProbeRequirement {
	private ProbeType[] requiredProbeTypes;
	private AnalyzedProperty[] requiredAnalyzedproperties;
	private ExtensionType[] requiredExtensionTypes;	
	private ProbeRequirement first, second, not;
	
	public ProbeRequirement() {
		requiredProbeTypes=new ProbeType[0];
		requiredAnalyzedproperties=new AnalyzedProperty[0];
		requiredExtensionTypes=new ExtensionType[0];
	}
	
	public ProbeRequirement requireProbeTypes(ProbeType ... probeTypes) {
		
		return this;
	}
	
	public ProbeRequirement requireAnalyzedProperties(AnalyzedProperty ... analyzedproperties) {
		
		return this;
	}
	
	public ProbeRequirement requireExtensionTyes(ExtensionType ... extensionTypes) {
		
		return this;		
	}
	
	// Freie Funktion?
	
	public ProbeRequirement orRequirement(ProbeRequirement firstReq, ProbeRequirement secondReq) {
		
		return this;
	}
	
	public ProbeRequirement notRequirement(ProbeRequirement req) {
		
		return this;
	}
	
	public boolean canBeExecuted() {
		
		return true;
	}
	
	private boolean analyzedPropertiesFulfilled() {
		return true;
	}	
	
	private boolean extensionTypesFulfilled() {
		return true;
	}	
	
	private boolean orFulfilled() {
		return true;
	}	
	
	private boolean notFulfilled() {
		return true;
	}
}
