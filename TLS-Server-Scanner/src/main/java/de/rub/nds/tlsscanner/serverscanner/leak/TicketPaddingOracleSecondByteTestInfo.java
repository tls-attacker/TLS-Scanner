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

    public TicketPaddingOracleSecondByteTestInfo(
            ProtocolVersion version, TicketPaddingOracleVectorLast previousVector) {
        super(version, previousVector.offset);
        this.previousVector = previousVector;
    }

    @Override
    public List<String> getFieldNames() {
        List<String> ret = new ArrayList<>(super.getFieldNames());
        ret.add("previousVector");
        return ret;
    }

    @Override
    public List<String> getFieldValues() {
        List<String> ret = new ArrayList<>(super.getFieldValues());
        ret.add(previousVector.toString());
        return ret;
    }

    @Override
    public String getTechnicalName() {
        return super.getTechnicalName() + ":" + previousVector.toString();
    }

    @Override
    public String getPrintableName() {
        return super.getPrintableName() + "\t" + previousVector.toString();
    }

    public TicketPaddingOracleVectorLast getPreviousVector() {
        return this.previousVector;
    }

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

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), previousVector);
    }
}
