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
 * Abstract subclass of {@link Requirement} to represent a requirement which can be evaluated
 * directly to a boolean value. Requirements of this type contain one or more parameters of an Enum
 * type which are compared to results in the report.
 */
public abstract class BooleanRequirement extends Requirement {
    protected final Enum<?>[] parameters;
    protected List<Enum<?>> missingParameters;

    /**
     * @param parameters the parameters of the {@link Requirement}.
     */
    protected BooleanRequirement(Enum<?>[] parameters) {
        this.parameters = parameters;
        this.missingParameters = new ArrayList<>();
    }

    @Override
    public String toString() {
        return Arrays.stream(parameters).map(Enum::name).collect(Collectors.joining(", "));
    }

    @Override
    public Enum<?>[] getRequirement() {
        return parameters;
    }
}
