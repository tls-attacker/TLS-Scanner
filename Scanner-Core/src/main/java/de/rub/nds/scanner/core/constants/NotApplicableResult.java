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

public class NotApplicableResult implements TestResult, Serializable {

    private final AnalyzedProperty property;
    private final String reason;

    public NotApplicableResult(AnalyzedProperty name, String reason) {
        this.property = name;
        this.reason = reason;
    }

    @Override
    public String name() {
        return property.getName();
    }

    @Override
    public boolean isRealResult() {
        return false;
    }

    public String getReason() {
        return reason;
    }
}
