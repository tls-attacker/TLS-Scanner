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

    public TicketPaddingOracleLastByteTestInfo(ProtocolVersion version, Integer paddingIvOffset) {
        this.version = version;
        this.paddingIvOffset = paddingIvOffset;
    }

    @Override
    public List<String> getFieldNames() {
        return Arrays.asList("version", "paddingIvOffset");
    }

    @Override
    public List<String> getFieldValues() {
        return Arrays.asList(version.name(), "" + paddingIvOffset);
    }

    @Override
    public String getTechnicalName() {
        return version.name() + ":PaddingOffset=" + paddingIvOffset;
    }

    @Override
    public String getPrintableName() {
        return version.name() + "\tPaddingOffset=" + paddingIvOffset;
    }

    public ProtocolVersion getVersion() {
        return this.version;
    }

    public Integer getPaddingIvOffset() {
        return this.paddingIvOffset;
    }

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

    @Override
    public int hashCode() {
        return Objects.hash(version, paddingIvOffset);
    }
}
