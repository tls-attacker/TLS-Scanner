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

/**
 * Abstract subclass of {@link Requirement} to represent a requirement which implements logical
 * functions for a complete requirement system.
 */
public abstract class LogicRequirement extends Requirement {
    protected final Requirement[] parameters;
    protected List<Requirement> missingParameters;

    /**
     * @param parameters the parameters of the {@link Requirement}.
     */
    protected LogicRequirement(Requirement[] parameters) {
        this.parameters = parameters;
        this.missingParameters = new ArrayList<>();
    }

    /**
     * Concatenates all appearing requirements in an Array of Enums, regardless of logical context.
     */
    @Override
    public Enum<?>[] getRequirement() {
        List<Enum<?>> requirements = new ArrayList<>();
        for (Requirement parameter : parameters) {
            if (parameter.getClass().equals(BooleanRequirement.class)) {
                requirements.addAll(Arrays.asList(parameter.getRequirement()));
            }
            if (parameter.getClass().equals(LogicRequirement.class)) {
                for (Requirement parametersParameter :
                        ((LogicRequirement) parameter).getParameters()) {
                    requirements.addAll(Arrays.asList(parametersParameter.getRequirement()));
                }
            }
        }
        return (Enum<?>[]) requirements.toArray();
    }

    /**
     * @return the array of parameters of type Requirement
     */
    public Requirement[] getParameters() {
        return parameters;
    }

    @Override
    public String toString() {
        return Arrays.stream(parameters).map(Requirement::name).collect(Collectors.joining(","));
    }
}
