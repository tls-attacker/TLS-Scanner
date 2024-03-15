/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.scanner.core.constants;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/** Enum which represents specific failure {@link TestResult}s. */
@XmlRootElement(name = "result")
@XmlAccessorType(XmlAccessType.FIELD)
public enum FailureResult implements TestResult {
    MISSING_CLIENT_HELLO;

    private FailureResult() {}
}
