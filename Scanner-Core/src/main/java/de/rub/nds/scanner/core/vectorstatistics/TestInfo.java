/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.vectorstatistics;

public abstract class TestInfo {

    public abstract String getTechnicalName();

    public abstract String getPrintableName();

    @Override
    public abstract boolean equals(Object o);

    @Override
    public abstract int hashCode();
}
