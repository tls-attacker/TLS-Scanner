/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket;

import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.tlsscanner.serverscanner.leak.TicketPaddingOracleLastByteTestInfo;
import de.rub.nds.tlsscanner.serverscanner.leak.TicketPaddingOracleSecondByteTestInfo;
import java.io.Serializable;
import java.util.List;

public class TicketPaddingOracleOffsetResult implements Serializable {

    private final InformationLeakTest<TicketPaddingOracleLastByteTestInfo> lastByteLeakTest;
    private final List<InformationLeakTest<TicketPaddingOracleSecondByteTestInfo>>
            secondByteLeakTests;

    public TicketPaddingOracleOffsetResult(
            InformationLeakTest<TicketPaddingOracleLastByteTestInfo> lastByteLeakTest,
            List<InformationLeakTest<TicketPaddingOracleSecondByteTestInfo>> secondByteLeakTests) {
        this.lastByteLeakTest = lastByteLeakTest;
        this.secondByteLeakTests = secondByteLeakTests;
    }

    public InformationLeakTest<TicketPaddingOracleLastByteTestInfo> getLastByteLeakTest() {
        return this.lastByteLeakTest;
    }

    public List<InformationLeakTest<TicketPaddingOracleSecondByteTestInfo>>
            getSecondByteLeakTests() {
        return this.secondByteLeakTests;
    }
}
