/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket;

import java.util.List;

import de.rub.nds.tlsscanner.serverscanner.leak.info.TicketPoLastByteTestInfo;
import de.rub.nds.tlsscanner.serverscanner.leak.info.TicketPoSecondByteTestInfo;
import de.rub.nds.tlsscanner.serverscanner.vectorstatistics.InformationLeakTest;

public class TicketPaddingOracleOffsetResult {

    private final InformationLeakTest<TicketPoLastByteTestInfo> lastByteLeakTest;
    private final List<InformationLeakTest<TicketPoSecondByteTestInfo>> secondByteLeakTests;

    public TicketPaddingOracleOffsetResult(InformationLeakTest<TicketPoLastByteTestInfo> lastByteLeakTest,
        List<InformationLeakTest<TicketPoSecondByteTestInfo>> secondByteLeakTests) {
        this.lastByteLeakTest = lastByteLeakTest;
        this.secondByteLeakTests = secondByteLeakTests;
    }

    public InformationLeakTest<TicketPoLastByteTestInfo> getLastByteLeakTest() {
        return this.lastByteLeakTest;
    }

    public List<InformationLeakTest<TicketPoSecondByteTestInfo>> getSecondByteLeakTests() {
        return this.secondByteLeakTests;
    }

}
