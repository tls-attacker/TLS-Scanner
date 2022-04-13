/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe;

import de.rub.nds.scanner.core.config.ScannerConfig;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.ScannerProbe;
import de.rub.nds.scanner.core.report.PerformanceData;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class TlsProbe<ScanConfig extends ScannerConfig, Report extends ScanReport> extends ScannerProbe<Report> {

    protected static final Logger LOGGER = LogManager.getLogger();

    protected final ScanConfig scannerConfig;

    private final ParallelExecutor parallelExecutor;
    
    protected List<TlsAnalyzedProperty> properties;
    private Map<TlsAnalyzedProperty, TestResult> propertiesMap;

    protected TlsProbe(ParallelExecutor parallelExecutor, TlsProbeType type, ScanConfig scannerConfig) {
        super(type);
        this.scannerConfig = scannerConfig;
        this.parallelExecutor = parallelExecutor;
        this.properties = new ArrayList<>();        
    }

    public final ScanConfig getScannerConfig() {
        return scannerConfig;
    }

    public final void executeState(State... states) {
        this.executeState(new ArrayList<>(Arrays.asList(states)));

    }

    public final void executeState(List<State> states) {
        parallelExecutor.bulkExecuteStateTasks(states);
        if (getWriter() != null) {
            for (State state : states) {
                getWriter().extract(state);
            }
        }
    }

    public ParallelExecutor getParallelExecutor() {
        return parallelExecutor;
    }
    
    protected void setPropertyReportValue(TlsAnalyzedProperty aProp, TestResult result) {
    	if (this.propertiesMap!=null) {
    		if (this.propertiesMap.containsKey(aProp))
    			this.propertiesMap.replace(aProp, result);
    		else // avoid unregistered properties are set
    			LOGGER.error(aProp.name() + " was set in " + this.getClass() + " but had not been registred!"); 
    	}
    	else {
    		this.propertiesMap = new HashMap<>();
    		for (TlsAnalyzedProperty property : this.properties)
    			this.propertiesMap.put(property, null);    		
    	}
    }
    
    // can be overwritten if some data must be set manually
    protected abstract void mergeData(Report report);
    
    public void merge(Report report) {
    	// catch case that no properties are set
    	if(this.propertiesMap==null) {
    		this.propertiesMap = new HashMap<>();
    		for (TlsAnalyzedProperty property : this.properties) {
    			LOGGER.error("Unassigned property " + property.name() + " in " + this.getClass());
    			this.propertiesMap.put(property, TestResults.UNASSIGNED_ERROR);   
    		}
    	} else {    	
	    	// check whether every property has been set
	    	for (TlsAnalyzedProperty aProp : this.properties) {
	    		if (this.propertiesMap.get(aProp) == null) {
	    			LOGGER.error("Unassigned property " + aProp.name() + " in " + this.getClass());
	    			this.propertiesMap.replace(aProp, TestResults.UNASSIGNED_ERROR);
	    		}    		
	    	}
    	}
    	// merge data
    	if (this.startTime != 0 && this.stopTime != 0) 
            report.getPerformanceList().add(new PerformanceData(this.type, this.startTime, this.stopTime));        
    	for (TlsAnalyzedProperty aProp : this.properties)
        	report.putResult(aProp, this.propertiesMap.get(aProp)); 
   		this.mergeData(report);
    }
}
