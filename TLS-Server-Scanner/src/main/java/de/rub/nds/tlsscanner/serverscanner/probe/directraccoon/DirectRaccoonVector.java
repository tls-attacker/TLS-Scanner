/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.directraccoon;

import de.rub.nds.tlsattacker.attacks.general.Vector;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.Objects;

public class DirectRaccoonVector implements Vector {

    private final DirectRaccoonWorkflowType type;

    private final ProtocolVersion version;

    private final CipherSuite suite;

    private final boolean pmsWithNullByte;

    public DirectRaccoonVector(DirectRaccoonWorkflowType type, ProtocolVersion version, CipherSuite suite,
        boolean pmsWithNullByte) {
        this.type = type;
        this.version = version;
        this.suite = suite;
        this.pmsWithNullByte = pmsWithNullByte;
    }

    public boolean isPmsWithNullByte() {
        return pmsWithNullByte;
    }

    public DirectRaccoonWorkflowType getWorkflowType() {
        return type;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public CipherSuite getSuite() {
        return suite;
    }

    public String getVectorName() {
        String name = type.name();
        if (pmsWithNullByte) {
            name += "-with nullByte";
        } else {
            name += "-without nullByte";
        }
        return name;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 97 * hash + Objects.hashCode(this.type);
        hash = 97 * hash + Objects.hashCode(this.version);
        hash = 97 * hash + Objects.hashCode(this.suite);
        hash = 97 * hash + (this.pmsWithNullByte ? 1 : 0);
        return hash;
    }

    @Override
    public String toString() {
        return "DirectRaccoonVector{" + "type=" + type + ", version=" + version + ", suite=" + suite
            + ", pmsWithNullByte=" + pmsWithNullByte + '}';
    }

    @Override
    public String getName() {
        if (pmsWithNullByte) {
            return "PMS starts with nullByte";
        } else {
            return "PMS does NOT start with nullByte";
        }

    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final DirectRaccoonVector other = (DirectRaccoonVector) obj;
        if (this.pmsWithNullByte != other.pmsWithNullByte) {
            return false;
        }
        if (this.type != other.type) {
            return false;
        }
        if (this.version != other.version) {
            return false;
        }
        if (this.suite != other.suite) {
            return false;
        }
        return true;
    }
}
