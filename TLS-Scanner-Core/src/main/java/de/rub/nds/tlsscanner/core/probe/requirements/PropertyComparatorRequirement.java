package de.rub.nds.tlsscanner.core.probe.requirements;

import java.util.Collection;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.MapResult;
import de.rub.nds.scanner.core.constants.SetResult;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.requirements.BooleanRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;

public class PropertyComparatorRequirement extends BooleanRequirement {
	public static enum Operator{GREATER, SMALLER, EQUAL}
	
	Operator op;
	Integer[] values;
	
	protected PropertyComparatorRequirement(Operator op, Enum<?>[] parameters, Integer ... values) {
		super(parameters);
		this.op=op;
		this.values=values;
	}

	@Override
	protected boolean evaluateInternal(ScanReport report) {
		if(parameters.length!=values.length) {
			return false;
		}
		TestResult result;
		Collection<?> collection;
		for (int i=0; i<parameters.length; i++) {
			result = report.getResult((TlsAnalyzedProperty) parameters[i]);
			try{
				collection = ((ListResult<?>)result).getList();
			}
			catch(Exception e) {
				try {
				collection = ((SetResult<?>)result).getSet();
				}
				catch(Exception ex) {
					try {
						collection = ((MapResult<?,?>)result).getMap().keySet();
					}catch(Exception exc) {
						return false;
					}
				}
			}
			switch(op) {
			case EQUAL: 
				if (collection.size() != values[i]) {
					return false;
				}
				break;
			case GREATER:
				if (collection.size() <= values[i]) {
					return false;
				}
				break;
			case SMALLER:
				if (collection.size() >= values[i]) {
					return false;
				}
			}
		}
		return false;
	}

	@Override
	public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
		 if (evaluateInternal(report) == false) {
			 return next.getMissingRequirementIntern(missing.requires(new PropertyComparatorRequirement(op, parameters, values)), report);
		 }
		 return next.getMissingRequirementIntern(missing, report);
	}

}
