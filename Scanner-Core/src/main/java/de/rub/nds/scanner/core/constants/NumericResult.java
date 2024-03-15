/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.constants;

import java.io.Serializable;

/**
 * Represents {@link TestResult}s of type {@link Number}.
 *
 * @param <T> the type of Number.
 */
public class NumericResult<T extends Number> implements TestResult, Serializable {

    private final String name;
    private final T value;

    public NumericResult(T value, String name) {
        this.name = name;
        this.value = value;
    }

    public T getValue() {
        return value;
    }

    @Override
    public String name() {
        return name;
    }
}
