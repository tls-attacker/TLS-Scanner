/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.after;

import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.after.padding.ShakyEvaluationReport;
import de.rub.nds.tlsscanner.report.after.padding.ShakyType;
import de.rub.nds.tlsscanner.report.after.padding.ShakyVectorHolder;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleCipherSuiteFingerprint;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ShakyPaddingOracleEvaluation extends AfterProbe {

    private final static Logger LOGGER = LogManager.getLogger();

    public ShakyPaddingOracleEvaluation() {
    }

    @Override
    public void analyze(SiteReport report) {
        List<ShakyVectorHolder> vectorHolderList = new LinkedList<>();
        Boolean truePositive = null;
        if (report.getPaddingOracleShakyEvalResultList() != null) {
            for (PaddingOracleCipherSuiteFingerprint fingerprint : report.getPaddingOracleShakyEvalResultList()) {
                if (!fingerprint.isShakyScans() && fingerprint.getEqualityError() != EqualityError.NONE) {
                    LOGGER.info("Shaky Scan evaluation found a true positive padding oracle");
                    truePositive = true;
                } else {
                    ShakyVectorHolder vectorHolder = new ShakyVectorHolder(fingerprint);
                    vectorHolderList.add(vectorHolder);
                }
            }
            Boolean isConsistentAccrossCvPairs = isConsistent(vectorHolderList);
            ShakyType shakyType = extractShakyType(vectorHolderList);
            ShakyEvaluationReport shakyReport = new ShakyEvaluationReport(truePositive, shakyType, isConsistentAccrossCvPairs, vectorHolderList);
            if (vectorHolderList.size() > 0) {
                report.setPaddingOracleShakyReport(shakyReport);
                if (Objects.equals(shakyReport.getConsideredVulnerable(), Boolean.TRUE)) {
                    report.removeResult(AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE);
                    report.putResult(AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE, TestResult.TRUE);
                }
            }
        }
    }

    private ShakyType extractShakyType(List<ShakyVectorHolder> vectorHolderList) {
        ShakyType baseType = null;
        for (ShakyVectorHolder holder : vectorHolderList) {
            if (baseType == null) {
                baseType = holder.getShakyType();
            } else if (baseType != holder.getShakyType()) {
                baseType = ShakyType.MIXED;
                break;
            }
        }
        return baseType;
    }

    private Boolean isConsistent(List<ShakyVectorHolder> vectorHolderList) {
        if (vectorHolderList.size() > 1) { //There is more than one shaky vector generator
            boolean allEqual = true;
            for (ShakyVectorHolder holderOne : vectorHolderList) {
                if (holderOne.isAllVectorsShaky()) {
                    //Ok this is not useful
                    break;
                }
                for (ShakyVectorHolder holderTwo : vectorHolderList) {
                    if (!holderOne.getShakyIdentifierSet().equals(holderTwo.getShakyIdentifierSet())) {
                        //Not equals Identifiers acroos ciphersuite fingerprints
                        allEqual = false;
                    }
                }
            }
            return allEqual;
        } else {
            return true;
        }
    }

}
