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
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.vector.TicketPoVectorLast;

public class TicketPoSecondByteTestInfo extends TicketPoLastByteTestInfo {

    private final TicketPoVectorLast previousVector;

    public TicketPoSecondByteTestInfo(ProtocolVersion version, TicketPoVectorLast previousVector) {
        super(version, previousVector.offset);
        this.previousVector = previousVector;
    }

    @Override
    public String getTechnicalName() {
        return super.getTechnicalName() + ":" + previousVector.toString();
    }

    @Override
    public String getPrintableName() {
        return super.getPrintableName() + "\t" + previousVector.toString();
    }

    public TicketPoVectorLast getPreviousVector() {
        return this.previousVector;
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof TicketPoSecondByteTestInfo)) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }
        TicketPoSecondByteTestInfo sessionTicketPaddingOracleSecondByteTestInfo = (TicketPoSecondByteTestInfo) o;
        return Objects.equals(previousVector, sessionTicketPaddingOracleSecondByteTestInfo.previousVector);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), previousVector);
    }

}
