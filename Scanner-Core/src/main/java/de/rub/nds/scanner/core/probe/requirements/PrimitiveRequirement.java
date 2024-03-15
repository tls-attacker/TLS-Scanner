/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.probe.requirements;

import de.rub.nds.scanner.core.report.ScanReport;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Abstract subclass of {@link Requirement} to represent a requirement which can be evaluated
 * directly to a boolean value. Requirements of this type contain one or more parameters of any
 * type.
 */
public abstract class PrimitiveRequirement<R extends ScanReport<R>, T> extends Requirement<R> {
    protected final List<T> parameters;

    protected PrimitiveRequirement(List<T> parameters) {
        this.parameters = Collections.unmodifiableList(parameters);
    }

    public List<T> getParameters() {
        return parameters;
    }

    @Override
    public String toString() {
        return String.format(
                "%s[%s]",
                this.getClass().getSimpleName(),
                parameters.stream().map(Object::toString).collect(Collectors.joining(", ")));
    }
}
