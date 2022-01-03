/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.scan;

import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public abstract class ScanJobExecutor {

    public abstract SiteReport execute();

    public abstract void shutdown();
}
