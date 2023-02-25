package de.rub.nds.scanner.core.probe.requirements;

import java.util.Arrays;
import java.util.stream.Collectors;

public abstract class BooleanRequirement extends Requirement {
	/*
	 * Contains the parameters on which this requirement depends on.
	 */
	protected Enum<?>[] parameters;
	
	@Override
	public String toString() {
	    return Arrays.stream(parameters)
	                    .map(Enum::name)
	                    .collect(Collectors.joining(", "));
	}
}
