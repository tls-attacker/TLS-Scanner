package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Map;

public class PropertyRequirement extends Requirement{
	
	private final TlsAnalyzedProperty[] properties;
	
	public PropertyRequirement(Requirement next, TlsAnalyzedProperty... properties){
		super();
		this.properties = properties;
		this.next = next;
	}
	
	public PropertyRequirement(TlsAnalyzedProperty... properties){
		super();
		this.properties = properties;
	}
	
	@Override
	public boolean evaluate(ScanReport report) {
		if (properties == null || properties.length == 0)
			return next.evaluate(report);
	    Map<String, TestResult> apList = report.getResultMap();
	    for (TlsAnalyzedProperty ap : properties) {
          	if (apList.containsKey(ap.toString())) {
              	if (apList.get(ap.toString()) != TestResults.TRUE)
            	  	return false;
          	} else
        	  	return false;
      	}
	    return next.evaluate(report);
	}
	
	/**
	 * @return the required properties
	 */
	public TlsAnalyzedProperty[] getRequirement() {
		return properties;
	}
}
