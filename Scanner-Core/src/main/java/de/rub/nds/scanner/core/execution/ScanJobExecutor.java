/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.execution;

import de.rub.nds.scanner.core.report.ScanReport;

public abstract class ScanJobExecutor<Report extends ScanReport> {

    public abstract Report execute(Report report);

    public abstract void shutdown();
}
