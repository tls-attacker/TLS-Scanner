/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.afterprobe;

import de.rub.nds.scanner.core.report.ScanReport;

public abstract class AfterProbe<T extends ScanReport> {
    public abstract void analyze(T report);
}
