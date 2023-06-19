/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.List;

/**
 * Represents a {@link Requirement} for required {@link TlsAnalyzedProperty} properties which were
 * positively evaluated (TestResults.TRUE).
 */
public class PropertyTrueRequirement<R extends TlsScanReport<R>> extends PropertyRequirement<R> {
    public PropertyTrueRequirement(List<TlsAnalyzedProperty> properties) {
        super(TestResults.TRUE, properties);
    }

    public PropertyTrueRequirement(TlsAnalyzedProperty... properties) {
        super(TestResults.TRUE, properties);
    }
}
