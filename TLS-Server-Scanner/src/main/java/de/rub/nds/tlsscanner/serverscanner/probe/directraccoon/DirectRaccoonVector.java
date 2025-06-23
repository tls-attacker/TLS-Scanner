/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.directraccoon;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.vector.Vector;
import java.util.Objects;

public class DirectRaccoonVector implements Vector {

    private final DirectRaccoonWorkflowType type;

    private final ProtocolVersion version;

    private final CipherSuite suite;

    private final boolean pmsWithNullByte;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private DirectRaccoonVector() {
        this.type = null;
        this.version = null;
        this.suite = null;
        this.pmsWithNullByte = false;
    }

    /**
     * Constructs a new DirectRaccoonVector with the specified parameters.
     *
     * @param type The workflow type for this vector
     * @param version The TLS protocol version
     * @param suite The cipher suite to use
     * @param pmsWithNullByte Whether the pre-master secret starts with a null byte
     */
    public DirectRaccoonVector(
            DirectRaccoonWorkflowType type,
            ProtocolVersion version,
            CipherSuite suite,
            boolean pmsWithNullByte) {
        this.type = type;
        this.version = version;
        this.suite = suite;
        this.pmsWithNullByte = pmsWithNullByte;
    }

    /**
     * Checks if the pre-master secret starts with a null byte.
     *
     * @return true if the pre-master secret starts with a null byte, false otherwise
     */
    public boolean isPmsWithNullByte() {
        return pmsWithNullByte;
    }

    /**
     * Returns the workflow type of this vector.
     *
     * @return The DirectRaccoonWorkflowType
     */
    public DirectRaccoonWorkflowType getWorkflowType() {
        return type;
    }

    /**
     * Returns the TLS protocol version for this vector.
     *
     * @return The ProtocolVersion
     */
    public ProtocolVersion getVersion() {
        return version;
    }

    /**
     * Returns the cipher suite for this vector.
     *
     * @return The CipherSuite
     */
    public CipherSuite getSuite() {
        return suite;
    }

    /**
     * Returns a descriptive name for this vector including the workflow type and null byte status.
     *
     * @return The vector name string
     */
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
        return "DirectRaccoonVector{"
                + "type="
                + type
                + ", version="
                + version
                + ", suite="
                + suite
                + ", pmsWithNullByte="
                + pmsWithNullByte
                + '}';
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
