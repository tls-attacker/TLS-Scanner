/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.constants;

/** The interface for TestResults */
public interface TestResult {

    /**
     * @return the name of the TestResult.
     */
    String name();

    /**
     * Returns if the Result stored for the property contains actual information
     *
     * @return true by default
     */
    default boolean isRealResult() {
        return true;
    }
}
