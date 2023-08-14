/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;

/**
 * Represents a {@link Requirement} for required {@link TlsAnalyzedProperty} properties which were
 * negatively evaluated.
 */
public class ProtocolTypeFalseRequirement<ReportT extends TlsScanReport>
        extends ProtocolTypeRequirement<ReportT> {

    public ProtocolTypeFalseRequirement(ProtocolType protocolType) {
        super(false, protocolType);
    }
}
