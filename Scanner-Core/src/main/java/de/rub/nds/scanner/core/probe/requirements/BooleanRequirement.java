/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.probe.requirements;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public abstract class BooleanRequirement extends Requirement {
    protected final Enum<?>[] parameters;
    protected List<Enum<?>> missingParameters;

    protected BooleanRequirement(Enum<?>[] parameters) {
    	this.parameters=parameters;
    	this.missingParameters = new ArrayList<>();
    }
    
    @Override
    public String toString() {
        return Arrays.stream(parameters).map(Enum::name).collect(Collectors.joining(", "));
    }
    
    @Override
    public Enum<?>[] getRequirement(){
    	return parameters;
    }
}
