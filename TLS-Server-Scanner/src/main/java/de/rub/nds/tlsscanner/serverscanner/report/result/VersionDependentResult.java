/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import java.io.Serializable;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public abstract class VersionDependentResult implements Serializable {
    protected final ProtocolVersion protocolVersion;

    protected VersionDependentResult(ProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    public abstract void writeToSiteReport(SiteReport report);

    protected void putResult(SiteReport report, AnalyzedProperty property, boolean result, boolean resultToKeep) {
        putResult(report, property, TestResult.of(result), resultToKeep);
    }

    protected void putResult(SiteReport report, AnalyzedProperty property, TestResult result, boolean resultToKeep) {
        TestResult existingResult = report.getResult(property);
        boolean doKeep = (resultToKeep && existingResult == TestResult.TRUE)
            || (!resultToKeep && existingResult == TestResult.FALSE);
        if (!doKeep && (existingResult == TestResult.TRUE || existingResult == TestResult.FALSE)) {
            // if we already have a true or false, only store true or false from now on
            doKeep = !(result == TestResult.TRUE || result == TestResult.FALSE);
        }
        if (!doKeep) {
            report.putResult(property, result);
        }
    }

}
