/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.BooleanRequirement;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Collection;

/**
 * Represents a {@link Requirement} which requires a certain size of a {@link TlsAnalyzedProperty}
 * in the report. It contains the operators greater, smaller and equal. The comparision is
 * [parameter value] [Operator] [value to compare]. Furthermore, the evaluation function returns
 * false for illegal inputs.
 */
public class PropertyComparatorRequirement extends BooleanRequirement {
    private enum Operator {
        GREATER,
        SMALLER,
        EQUAL
    }

    public static Operator GREATER = Operator.GREATER;
    public static Operator SMALLER = Operator.SMALLER;
    public static Operator EQUAL = Operator.EQUAL;

    private Enum<?> parameter;
    private Integer value;

    /**
     * @param op the oerator for the requirement.
     * @param parameter the property to check of type {@link TlsAnalyzedProperty}.
     * @param value the value to compare with.
     */
    public PropertyComparatorRequirement(Operator op, Enum<?> parameter, Integer value) {
        super(new Operator[] {op});
        this.parameter = parameter;
        this.value = value;
    }

    @Override
    protected boolean evaluateInternal(ScanReport report) {
        if (parameter == null || value == null) {
            return false;
        }
        Collection<?> collection;
        try {
            collection = report.getListResult((TlsAnalyzedProperty) parameter).getList();
        } catch (Exception e) {
            try {
                collection = report.getSetResult((TlsAnalyzedProperty) parameter).getSet();
            } catch (Exception ex) {
                try {
                    collection =
                            report.getMapResult((TlsAnalyzedProperty) parameter).getMap().keySet();
                } catch (Exception exc) {
                    return false;
                }
            }
        }
        switch ((Operator) parameters[0]) {
            case EQUAL:
                if (collection.size() != value) {
                    return false;
                }
                break;
            case GREATER:
                if (collection.size() <= value) {
                    return false;
                }
                break;
            case SMALLER:
                if (collection.size() >= value) {
                    return false;
                }
        }

        return true;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateInternal(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(
                            new PropertyComparatorRequirement(
                                    (Operator) parameters[0], parameter, value)),
                    report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
