/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.padding.vector;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsscanner.core.vector.Vector;

public abstract class PaddingVector implements Vector {

    protected final String name;

    protected final String identifier;

    public PaddingVector(String name, String identifier) {
        this.name = name;
        this.identifier = identifier;
    }

    public abstract Record createRecord();

    public abstract int getRecordLength(
            CipherSuite testedSuite, ProtocolVersion testedVersion, int appDataLength);

    @Override
    public String getName() {
        return name;
    }

    public String getIdentifier() {
        return identifier;
    }
}
