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
	Integer value;
	
	public PropertyComparatorRequirement(Operator op, Enum<?> parameter, Integer value) {
		super(new Enum<?>[] {parameter});
		this.op=op;
		this.value=value;
	}

	@Override
	protected boolean evaluateInternal(ScanReport report) {
		if(parameters[0]==null || value == null) {
			return false;
		}
		TestResult result;
		Collection<?> collection;
		result = report.getResult((TlsAnalyzedProperty) parameters[0]);
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
			if (collection.size() != value) {
				return false;
			}
			break;
		case GREATER:
			if (collection.size() <= value) {
				return false;
			}
			break;
		case SMALLER:
			if (collection.size() >= value) {
				return false;
			}
		}
		
		return false;
	}

	@Override
	public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
		 if (evaluateInternal(report) == false) {
			 return next.getMissingRequirementIntern(missing.requires(new PropertyComparatorRequirement(op, parameters[0], value)), report);
		 }
		 return next.getMissingRequirementIntern(missing, report);
	}

}
