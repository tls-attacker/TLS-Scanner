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
import de.rub.nds.tlsscanner.core.vector.statistics.TestInfo;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class TicketPaddingOracleLastByteTestInfo extends TestInfo {
    private final ProtocolVersion version;

    /**
     * Offset used during this test. The Offset points to the IV of the padding (i.e. the second
     * last block). A value of 0 corresponds to the rightmost byte.
     */
    private final Integer paddingIvOffset;

    /** Default constructor for serialization. */
    @SuppressWarnings("unused")
    private TicketPaddingOracleLastByteTestInfo() {
        this.version = null;
        this.paddingIvOffset = null;
    }

    /**
     * Constructs a new TicketPaddingOracleLastByteTestInfo with the specified parameters.
     *
     * @param version the protocol version to test
     * @param paddingIvOffset the offset used during this test, pointing to the IV of the padding
     */
    public TicketPaddingOracleLastByteTestInfo(ProtocolVersion version, Integer paddingIvOffset) {
        this.version = version;
        this.paddingIvOffset = paddingIvOffset;
    }

    /**
     * Returns the names of the fields in this test info.
     *
     * @return a list containing "version" and "paddingIvOffset"
     */
    @Override
    public List<String> getFieldNames() {
        return Arrays.asList("version", "paddingIvOffset");
    }

    /**
     * Returns the values of the fields in this test info.
     *
     * @return a list containing the field values as strings
     */
    @Override
    public List<String> getFieldValues() {
        return Arrays.asList(version.name(), "" + paddingIvOffset);
    }

    /**
     * Returns a technical name for this test info.
     *
     * @return a string combining version and padding offset
     */
    @Override
    public String getTechnicalName() {
        return version.name() + ":PaddingOffset=" + paddingIvOffset;
    }

    /**
     * Returns a human-readable name for this test info.
     *
     * @return a tab-separated string of version and padding offset
     */
    @Override
    public String getPrintableName() {
        return version.name() + "\tPaddingOffset=" + paddingIvOffset;
    }

    /**
     * Returns the protocol version for this test.
     *
     * @return the protocol version
     */
    public ProtocolVersion getVersion() {
        return this.version;
    }

    /**
     * Returns the padding IV offset for this test.
     *
     * @return the padding IV offset
     */
    public Integer getPaddingIvOffset() {
        return this.paddingIvOffset;
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
        if (!(o instanceof TicketPaddingOracleLastByteTestInfo)) {
            return false;
        }
        TicketPaddingOracleLastByteTestInfo sessionTicketTestInfo =
                (TicketPaddingOracleLastByteTestInfo) o;
        return Objects.equals(version, sessionTicketTestInfo.version)
                && Objects.equals(paddingIvOffset, sessionTicketTestInfo.paddingIvOffset);
    }

    /**
     * Returns a hash code value for this test info.
     *
     * @return the hash code value
     */
    @Override
    public int hashCode() {
        return Objects.hash(version, paddingIvOffset);
    }
}
