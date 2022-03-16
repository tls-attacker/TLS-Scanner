/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.requirements;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResults;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class ProbeRequirement {
	private SiteReport report;
	private ProbeType[] requiredProbeTypes;
	private AnalyzedProperty[] requiredAnalyzedproperties;
	private ExtensionType[] requiredExtensionTypes;	
	private ProbeRequirement first, second, not;
	
	public ProbeRequirement(SiteReport report) {
		this.report=report;
	}
	
	public ProbeRequirement requireProbeTypes(ProbeType ... probeTypes) {
		this.requiredProbeTypes=probeTypes;
		return this;
	}
	
	public ProbeRequirement requireAnalyzedProperties(AnalyzedProperty ... analyzedProperties) {
		this.requiredAnalyzedproperties=analyzedProperties;
		return this;
	}
	
	public ProbeRequirement requireExtensionTyes(ExtensionType ... extensionTypes) {
		this.requiredExtensionTypes=extensionTypes;
		return this;		
	}
	
	// Freie Funktion?
	
	public ProbeRequirement orRequirement(ProbeRequirement firstReq, ProbeRequirement secondReq) {
		this.first=firstReq;
		this.second=secondReq;
		return this;
	}
	
	public ProbeRequirement notRequirement(ProbeRequirement req) {
		this.not=req;
		return this;
	}
	
	public boolean evaluateRequirements() {		
		return probeTypesFulfilled() && analyzedPropertiesFulfilled() && extensionTypesFulfilled() && orFulfilled() && notFulfilled();
	}
	
	private boolean probeTypesFulfilled() {
		if (this.requiredProbeTypes==null)
			return true;		
		for (ProbeType pt : this.requiredProbeTypes) {
			if (report.isProbeAlreadyExecuted(pt)==false) 
				return false;			
		}
		return true;
	}	
	
	private boolean analyzedPropertiesFulfilled() {
		if (this.requiredAnalyzedproperties==null)
			return true;
		for (AnalyzedProperty ap : this.requiredAnalyzedproperties) {
			if (report.getResultMap().containsKey(ap.toString())) {
				if (report.getResultMap().get(ap.toString())!= TestResults.TRUE)
					return false;
			}
			else
				return false;
		}
		return true;
	}	
	
	private boolean extensionTypesFulfilled() {
		if (this.requiredExtensionTypes==null)
			return true;
		for (ExtensionType et : this.requiredExtensionTypes) {
			if (!report.getSupportedExtensions().contains(et))
				return false;
		}
		return true;
	}	
	
	private boolean orFulfilled() {
		if (this.first==null && this.second==null)
			return true;
		boolean evalFirst = this.first.evaluateRequirements();
		boolean evalSecond = this.second.evaluateRequirements();
		
		if (this.first==null)
			return evalSecond;
		if (this.second==null)
			return evalFirst;
		return evalFirst || evalSecond;
	}	
	
	private boolean notFulfilled() {
		if (this.not==null)
			return true;		
		return !this.not.evaluateRequirements();
	}
}
