/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core;

import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.io.OutputStream;

public class TlsCoreTestReport extends TlsScanReport {
    @Override
    public void serializeToJson(OutputStream stream) {}
}
