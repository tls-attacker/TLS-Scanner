/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.AnalyzedProperty;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.io.Serializable;

public abstract class VersionDependentResult implements Serializable {
    protected final ProtocolVersion protocolVersion;

    protected VersionDependentResult(ProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    public abstract void writeToServerReport(ServerReport report);

    protected void putResult(
            ServerReport report, AnalyzedProperty property, boolean result, boolean resultToKeep) {
        putResult(report, property, TestResults.of(result), resultToKeep);
    }

    /**
     * Put result into given report. If a result already exists, this is merged. If no result
     * exists, {@code result} is written to the report. If a result exists and is not equivalent to
     * {@code resultToKeep}, {@code result} is written to the report. If a result exists and is
     * equivalent to {@code resultToKeep}, the existing result is not changed.
     *
     * <p>Example: If we pass {@code resultToKeep=true} and the report already stores {@code TRUE},
     * then no other result can overwrite this result. This is useful if other versions might result
     * in false, for example if only one version is vulnerable. Analogously for {@code
     * resultToKeep=false} (for results stating a countermeasure works). Further, any values that
     * are not TRUE or FALSE (errors) are overwritten.
     *
     * @param report Report to put the result into.
     * @param property Property to set in the report.
     * @param result New result to merge.
     * @param resultToKeep Result value that should not be overwritten.
     */
    protected void putResult(
            ServerReport report,
            AnalyzedProperty property,
            TestResult result,
            boolean resultToKeep) {
        TestResult existingResult = report.getResult(property);
        boolean doKeep =
                (resultToKeep && existingResult == TestResults.TRUE)
                        || (!resultToKeep && existingResult == TestResults.FALSE);
        if (!doKeep
                && (existingResult == TestResults.TRUE || existingResult == TestResults.FALSE)) {
            // if we already have a true or false, only store true or false from now on
            doKeep = !(result == TestResults.TRUE || result == TestResults.FALSE);
        }
        if (!doKeep) {
            report.putResult(property, result);
        }
    }
}
