/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.clientscanner.constants.CompositeModulusType;
import de.rub.nds.tlsscanner.clientscanner.constants.SmallSubgroupType;
import de.rub.nds.tlsscanner.clientscanner.probe.result.dhe.CompositeModulusResult;
import de.rub.nds.tlsscanner.clientscanner.probe.result.dhe.SmallSubgroupResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.HashMap;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DheParameterResult extends ProbeResult<ClientReport> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Integer lowestDheModulusLength;
    private final Integer highestDheModulusLength;
    private final List<SmallSubgroupResult> smallSubgroupResults;
    private final List<CompositeModulusResult> compositeModulusResultList;
    private final HashMap<CompositeModulusType, TlsAnalyzedProperty>
            compositeModulusTypeToPropertyMapping;
    private final HashMap<SmallSubgroupType, TlsAnalyzedProperty>
            smallSubgroupTypeToPropertyMapping;

    public DheParameterResult(
            Integer lowestDheModulusLength,
            Integer highestDheModulusLength,
            List<SmallSubgroupResult> smallSubgroupResults,
            List<CompositeModulusResult> compositeModulusResultList) {
        super(TlsProbeType.DHE_PARAMETERS);
        this.lowestDheModulusLength = lowestDheModulusLength;
        this.highestDheModulusLength = highestDheModulusLength;
        this.smallSubgroupResults = smallSubgroupResults;
        this.compositeModulusResultList = compositeModulusResultList;
        compositeModulusTypeToPropertyMapping = getCompositeModulusTypeMap();
        smallSubgroupTypeToPropertyMapping = getSmallSubgroupTypeMap();
    }

    private HashMap<CompositeModulusType, TlsAnalyzedProperty> getCompositeModulusTypeMap() {
        HashMap<CompositeModulusType, TlsAnalyzedProperty> compositeModulusTypeMap =
                new HashMap<>();
        compositeModulusTypeMap.put(
                CompositeModulusType.EVEN, TlsAnalyzedProperty.SUPPORTS_EVEN_MODULUS);
        compositeModulusTypeMap.put(
                CompositeModulusType.MOD3, TlsAnalyzedProperty.SUPPORTS_MOD3_MODULUS);
        return compositeModulusTypeMap;
    }

    private HashMap<SmallSubgroupType, TlsAnalyzedProperty> getSmallSubgroupTypeMap() {
        HashMap<SmallSubgroupType, TlsAnalyzedProperty> smallSubgroupTypeMap = new HashMap<>();
        smallSubgroupTypeMap.put(
                SmallSubgroupType.MODULUS_ONE, TlsAnalyzedProperty.SUPPORTS_MODULUS_ONE);
        smallSubgroupTypeMap.put(
                SmallSubgroupType.GENERATOR_ONE, TlsAnalyzedProperty.SUPPORTS_GENERATOR_ONE);
        return smallSubgroupTypeMap;
    }

    @Override
    protected void mergeData(ClientReport report) {
        report.setLowestPossibleDheModulusSize(lowestDheModulusLength);
        report.setHighestPossibleDheModulusSize(highestDheModulusLength);
        mergeCompositeModulusResult(report);
        mergeSmallSubgroupResult(report);
    }

    private void mergeCompositeModulusResult(ClientReport report) {
        if (compositeModulusResultList == null) {
            for (TlsAnalyzedProperty property : compositeModulusTypeToPropertyMapping.values()) {
                report.putResult(property, TestResults.COULD_NOT_TEST);
            }
            return;
        }
        for (CompositeModulusResult compositeResult : compositeModulusResultList) {
            TlsAnalyzedProperty property =
                    compositeModulusTypeToPropertyMapping.get(compositeResult.getType());
            if (property == null) {
                LOGGER.warn(
                        "No report property configured for composite modulus type {}, ignoring.",
                        compositeResult.getType().name());
                continue;
            }
            report.putResult(property, compositeResult.getResult());
        }
    }

    private void mergeSmallSubgroupResult(ClientReport report) {
        if (smallSubgroupResults == null) {
            for (TlsAnalyzedProperty property : smallSubgroupTypeToPropertyMapping.values()) {
                report.putResult(property, TestResults.COULD_NOT_TEST);
            }
            return;
        }
        for (SmallSubgroupResult smallSubgroupResult : smallSubgroupResults) {
            TlsAnalyzedProperty property =
                    smallSubgroupTypeToPropertyMapping.get(smallSubgroupResult.getType());
            if (property == null) {
                LOGGER.warn(
                        "No report property configured for small subgroup type {}, ignoring.",
                        smallSubgroupResult.getType().name());
                continue;
            }
            report.putResult(property, smallSubgroupResult.getResult());
        }
    }
}
