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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResults;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.List;

public class ProbeRequirement {
	private SiteReport report;
	private ProbeType[] requiredProbeTypes;
	private AnalyzedProperty[] requiredAnalyzedproperties, requiredAnalyzedpropertiesNot;
	private ExtensionType[] requiredExtensionTypes;	
	private ProtocolVersion[] requiredProtocolVersions;
	private ProbeRequirement not;
	private ProbeRequirement[] requiredOR;

	public ProbeRequirement(SiteReport report) {
		this.report=report;
	}
	
	public ProbeRequirement requireProbeTypes(ProbeType ... probeTypes) {
		this.requiredProbeTypes=probeTypes;
		return this;
	}
	
	public ProbeRequirement requireProtocolVersions(ProtocolVersion ... protocolVersions) {
		this.requiredProtocolVersions=protocolVersions;
		return this;
	}
	
	public ProbeRequirement requireAnalyzedProperties(AnalyzedProperty ... analyzedProperties) {
		this.requiredAnalyzedproperties=analyzedProperties;
		return this;
	}
	
	public ProbeRequirement requireAnalyzedPropertiesNot(AnalyzedProperty ... analyzedPropertiesNot) {
		this.requiredAnalyzedpropertiesNot=analyzedPropertiesNot;
		return this;
	}
	
	public ProbeRequirement requireExtensionTyes(ExtensionType ... extensionTypes) {
		this.requiredExtensionTypes=extensionTypes;
		return this;		
	}
	
	public ProbeRequirement orRequirement(ProbeRequirement ... orReq ) {
		this.requiredOR=orReq;
		return this;
	}
	
	public ProbeRequirement notRequirement(ProbeRequirement req) {
		this.not=req;
		return this;
	}
	
	public boolean evaluateRequirements() {		
		return probeTypesFulfilled() && analyzedProtocolVersionsFulfilled() && analyzedPropertiesFulfilled() && extensionTypesFulfilled() && orFulfilled() && notFulfilled() && analyzedPropertiesNotFulfilled();
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
	
	private boolean analyzedProtocolVersionsFulfilled() {
		if (this.requiredProtocolVersions==null)
			return true;
		List<ProtocolVersion> pvList = report.getVersions();
		if (pvList==null)
			return false;
		for (ProtocolVersion pv : this.requiredProtocolVersions) {
			if (!pvList.contains(pv))
				return false;
		}
		return true;
	}
	
	private boolean analyzedPropertiesNotFulfilled() {
		if (this.requiredAnalyzedpropertiesNot==null)
			return true;
		for (AnalyzedProperty ap : this.requiredAnalyzedpropertiesNot) {
			if (report.getResultMap().containsKey(ap.toString())) {
				if (report.getResultMap().get(ap.toString())!= TestResults.FALSE)
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
		if (report.getSupportedExtensions() == null) 
			return false;
		for (ExtensionType et : this.requiredExtensionTypes) {
			if(!report.getSupportedExtensions().contains(et)) 
				return false;
		}
		return true;
	}	
	
	private boolean orFulfilled() {
		if (this.requiredOR==null)
			return true;
		for (ProbeRequirement pReq : this.requiredOR) {
			if(pReq.evaluateRequirements())
				return true;
		}
		return false;
	}	
	
	private boolean notFulfilled() {
		if (this.not==null)
			return true;		
		return !this.not.evaluateRequirements();
	}
	
	/**
	 * @return the requiredProbeTypes
	 */
	public ProbeType[] getRequiredProbeTypes() {
		return requiredProbeTypes;
	}

	/**
	 * @return the requiredAnalyzedproperties
	 */
	public AnalyzedProperty[] getRequiredAnalyzedproperties() {
		return this.requiredAnalyzedproperties;
	}

	/**
	 * @return the requiredAnalyzedpropertiesNot
	 */
	public AnalyzedProperty[] getRequiredAnalyzedpropertiesNot() {
		return this.requiredAnalyzedpropertiesNot;
	}
	
	/**
	 * @return the requiredExtensionTypes
	 */
	public ExtensionType[] getRequiredExtensionTypes() {
		return this.requiredExtensionTypes;
	}
	
	/**
	 * @return the requiredProtocolVersions
	 */
	public ProtocolVersion[] getRequiredProtocolVersions() {
		return this.requiredProtocolVersions;
	}

	/**
	 * @return the or ProbeRequirements
	 */
	public ProbeRequirement[] getORRequirements() {
		return this.requiredOR;
	}

	/**
	 * @return the inverted ProbeRequirement
	 */
	public ProbeRequirement getNot() {
		return this.not;
	}
}
