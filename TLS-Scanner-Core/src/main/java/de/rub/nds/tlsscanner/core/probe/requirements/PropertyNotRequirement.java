package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Map;

public class PropertyNotRequirement extends Requirement{

private final TlsAnalyzedProperty[] propertiesNot;
	
public PropertyNotRequirement(TlsAnalyzedProperty... propertiesNot){
	super();
	this.propertiesNot = propertiesNot;
}
	
	@Override
	public boolean evaluate(ScanReport report) {
		if (propertiesNot == null || propertiesNot.length == 0)
			return next.evaluate(report);
	    Map<String, TestResult> apList = report.getResultMap();
	    for (TlsAnalyzedProperty ap : propertiesNot) {
          	if (apList.containsKey(ap.toString())) {
              	if (apList.get(ap.toString()) != TestResults.FALSE)
            	  	return false;
          	} else
        	  	return false;
      	}
	    return next.evaluate(report);
	}
	
	/**
	 * @return the required propertiesNot
	 */
	public TlsAnalyzedProperty[] getRequirement() {
		return propertiesNot;
	}
}
