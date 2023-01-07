/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.constants;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Set;

/**
 * Represents {@link TestResult}s of type {@link Set} with objects of type T.
 *
 * @param <T> the type of which the SetResult consists.
 */
@XmlRootElement(name = "result")
@XmlAccessorType(XmlAccessType.FIELD)
public class SetResult<T> implements TestResult {

    private final String name;
    private final Set<T> set;

    /**
     * The constructor for the SetResult. Use property.name() for the name parameter.
     *
     * @param set The result set.
     * @param name The name of the SetResult object.
     */
    public SetResult(Set<T> set, String name) {
        this.set = set;
        this.name = name;
    }

    /**
     * @return The set of the SetResult.
     */
    public Set<T> getSet() {
        return this.set;
    }

    @Override
    public String name() {
        return this.name;
    }
}
