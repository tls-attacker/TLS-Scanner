/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.leak;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketPaddingOracleVectorLast;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class TicketPaddingOracleSecondByteTestInfo extends TicketPaddingOracleLastByteTestInfo {

    private final TicketPaddingOracleVectorLast previousVector;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private TicketPaddingOracleSecondByteTestInfo() {
        super(null, null);
        this.previousVector = null;
    }

    /**
     * Constructs a new TicketPaddingOracleSecondByteTestInfo with the specified parameters.
     *
     * @param version the protocol version to test
     * @param previousVector the previous vector used in the first byte test
     */
    public TicketPaddingOracleSecondByteTestInfo(
            ProtocolVersion version, TicketPaddingOracleVectorLast previousVector) {
        super(version, previousVector.offset);
        this.previousVector = previousVector;
    }

    /**
     * Returns the names of the fields in this test info.
     *
     * @return a list containing the parent field names plus "previousVector"
     */
    @Override
    public List<String> getFieldNames() {
        List<String> ret = new ArrayList<>(super.getFieldNames());
        ret.add("previousVector");
        return ret;
    }

    /**
     * Returns the values of the fields in this test info.
     *
     * @return a list containing the parent field values plus the previous vector string
     */
    @Override
    public List<String> getFieldValues() {
        List<String> ret = new ArrayList<>(super.getFieldValues());
        ret.add(previousVector.toString());
        return ret;
    }

    /**
     * Returns a technical name for this test info.
     *
     * @return the parent technical name concatenated with the previous vector
     */
    @Override
    public String getTechnicalName() {
        return super.getTechnicalName() + ":" + previousVector.toString();
    }

    /**
     * Returns a human-readable name for this test info.
     *
     * @return the parent printable name concatenated with the previous vector
     */
    @Override
    public String getPrintableName() {
        return super.getPrintableName() + "\t" + previousVector.toString();
    }

    /**
     * Returns the previous vector used in the first byte test.
     *
     * @return the previous vector
     */
    public TicketPaddingOracleVectorLast getPreviousVector() {
        return this.previousVector;
    }

    /**
     * Checks if this test info is equal to another object.
     *
     * @param o the object to compare with
     * @return true if the objects are equal, false otherwise
     */
    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof TicketPaddingOracleSecondByteTestInfo)) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        TicketPaddingOracleSecondByteTestInfo sessionTicketPaddingOracleSecondByteTestInfo =
                (TicketPaddingOracleSecondByteTestInfo) o;
        return Objects.equals(
                previousVector, sessionTicketPaddingOracleSecondByteTestInfo.previousVector);
    }

    /**
     * Returns a hash code value for this test info.
     *
     * @return the hash code value
     */
    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), previousVector);
    }
}
