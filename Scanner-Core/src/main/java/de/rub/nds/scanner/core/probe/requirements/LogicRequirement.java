/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.probe.requirements;

import java.util.Arrays;
import java.util.stream.Collectors;

public abstract class LogicRequirement extends Requirement {
    /*
     * Contains the requirement(s) on which this requirement operates.
     */
    protected Requirement[] parameters;
    
    /*what to do with that? OR and NOT enum to include and make the array a boolean expression? */
    @Override
    public Enum<?>[] getRequirement(){
    	return parameters[0].getRequirement();
    }
    
        @Override
        public String toString() {
            return Arrays.stream(parameters)
                    .map(Requirement::name)
                    .collect(Collectors.joining(","));
        }
}
