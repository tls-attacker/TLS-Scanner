/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.leak.info;

import java.util.Objects;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

public class TicketPoLastByteTestInfo extends TestInfo {
    private final ProtocolVersion version;

    /**
     * Offset used during this test. The Offset points to the IV of the padding (i.e. the second last block). A value of
     * 0 corresponds to the rightmost byte.
     */
    private final Integer paddingIvOffset;

    public TicketPoLastByteTestInfo(ProtocolVersion version, Integer paddingIvOffset) {
        this.version = version;
        this.paddingIvOffset = paddingIvOffset;
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
        if (o == this)
            return true;
        if (!(o instanceof TicketPoLastByteTestInfo)) {
            return false;
        }
        TicketPoLastByteTestInfo sessionTicketTestInfo = (TicketPoLastByteTestInfo) o;
        return Objects.equals(version, sessionTicketTestInfo.version)
            && Objects.equals(paddingIvOffset, sessionTicketTestInfo.paddingIvOffset);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, paddingIvOffset);
    }

}
