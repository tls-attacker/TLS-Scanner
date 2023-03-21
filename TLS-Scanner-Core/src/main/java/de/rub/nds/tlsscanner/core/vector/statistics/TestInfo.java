/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.vector.statistics;

import java.util.List;

public abstract class TestInfo {

    public abstract String getTechnicalName();

    public abstract List<String> getFieldNames();

    public abstract List<String> getFieldValues();

    public abstract String getPrintableName();

    @Override
    public abstract boolean equals(Object o);

    @Override
    public abstract int hashCode();
}
