/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.report.requirements;

import java.io.Serializable;
import java.util.function.Predicate;

import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.NotExecutedResult;

public abstract class ProbeRequirements {
    private static True TRUE = null;

    public static True TRUE() {
        if (TRUE == null) {
            TRUE = new True(null);
        }
        return TRUE;
    }

    public ProbeRequirements needResult(Class<? extends IProbe> requiredClass) {
        return new NeedResult(this, requiredClass);
    }

    public ProbeRequirements needResultOfType(Class<? extends IProbe> requiredClass,
            Class<? extends Serializable> resType) {
        return new NeedResultOfType(this, requiredClass, resType);
    }

    public <T extends Serializable> ProbeRequirements needResultOfTypeMatching(Class<? extends IProbe> requiredClass,
            Class<T> resType, Predicate<T> predicate, String notMatchedDescription) {
        return new NeedResultOfTypeMatching<>(this, requiredClass, resType, predicate, notMatchedDescription);
    }

    public abstract boolean evaluateRequirementsMet(ClientReport report);

    protected abstract NotExecutedResult evaluateWhyRequirementsNotMetInternal(Class<? extends IProbe> probe,
            ClientReport report);

    public final NotExecutedResult evaluateWhyRequirementsNotMet(Class<? extends IProbe> probe, ClientReport report) {
        NotExecutedResult res = evaluateWhyRequirementsNotMetInternal(probe, report);
        if (res != null) {
            return res;
        }
        return NotExecutedResult.UNKNOWN_ERROR(probe);
    }

    public static class True extends ProbeRequirements {
        protected ProbeRequirements previous;

        protected True(ProbeRequirements previous) {
            this.previous = previous;
        }

        @Override
        public boolean evaluateRequirementsMet(ClientReport report) {
            return previous == null || previous.evaluateRequirementsMet(report);
        }

        @Override
        public NotExecutedResult evaluateWhyRequirementsNotMetInternal(Class<? extends IProbe> probe,
                ClientReport report) {
            if (previous == null) {
                return null;
            }
            return previous.evaluateWhyRequirementsNotMetInternal(probe, report);
        }
    }

    public static class NeedResult extends True {
        protected final Class<? extends IProbe> requiredClass;

        protected NeedResult(ProbeRequirements previous, Class<? extends IProbe> requiredClass) {
            super(previous);
            this.requiredClass = requiredClass;
        }

        @Override
        public boolean evaluateRequirementsMet(ClientReport report) {
            return super.evaluateRequirementsMet(report) && report.hasResult(requiredClass);
        }

        @Override
        public NotExecutedResult evaluateWhyRequirementsNotMetInternal(Class<? extends IProbe> probe,
                ClientReport report) {
            NotExecutedResult ret = super.evaluateWhyRequirementsNotMetInternal(probe, report);
            if (ret != null) {
                return ret;
            }
            if (!report.hasResult(requiredClass)) {
                return NotExecutedResult.MISSING_DEPENDENT_RESULT(probe, requiredClass);
            }
            return null;
        }
    }

    public static class NeedResultOfType extends NeedResult {
        protected final Class<? extends Serializable> requiredResultType;

        protected NeedResultOfType(ProbeRequirements previous, Class<? extends IProbe> requiredClass,
                Class<? extends Serializable> resType) {
            super(previous, requiredClass);
            this.requiredResultType = resType;
        }

        @Override
        public boolean evaluateRequirementsMet(ClientReport report) {
            return super.evaluateRequirementsMet(report)
                    && requiredResultType.isInstance(report.getResult(requiredClass));
        }

        @Override
        public NotExecutedResult evaluateWhyRequirementsNotMetInternal(Class<? extends IProbe> probe,
                ClientReport report) {
            NotExecutedResult ret = super.evaluateWhyRequirementsNotMetInternal(probe, report);
            if (ret != null) {
                return ret;
            }
            Object res = report.getResult(requiredClass);
            if (!requiredResultType.isInstance(res)) {
                return new NotExecutedResult(
                        probe,
                        String.format(
                                "This probe could not be executed, as it depends on the result of the probe '%s' with type '%s' but type '%s' was found",
                                requiredClass.getName(), requiredResultType.getName(), res.getClass().getName()));
            }
            return null;
        }
    }

    public static class NeedResultOfTypeMatching<T extends Serializable> extends NeedResultOfType {
        protected final Predicate<T> predicate;
        protected final String notMatchedDescription;

        protected NeedResultOfTypeMatching(ProbeRequirements previous, Class<? extends IProbe> requiredClass,
                Class<T> resType, Predicate<T> predicate, String notMatchedDescription) {
            super(previous, requiredClass, resType);
            this.predicate = predicate;
            this.notMatchedDescription = notMatchedDescription;
        }

        @Override
        public boolean evaluateRequirementsMet(ClientReport report) {
            if (!super.evaluateRequirementsMet(report)) {
                return false;
            }
            @SuppressWarnings("unchecked")
            T t = (T) report.getResult(requiredClass);
            try {
                return predicate.test(t);
            } catch (RuntimeException e) {
                return false;
            }
        }

        @Override
        public NotExecutedResult evaluateWhyRequirementsNotMetInternal(Class<? extends IProbe> probe,
                ClientReport report) {
            NotExecutedResult ret = super.evaluateWhyRequirementsNotMetInternal(probe, report);
            if (ret != null) {
                return ret;
            }
            T res = (T) report.getResult(requiredClass);
            try {
                if (!predicate.test(res)) {
                    return new NotExecutedResult(probe, notMatchedDescription);
                }
            } catch (RuntimeException e) {
                return new NotExecutedResult(probe,
                        String.format("Failed to evaluate predicate [%s] %s", notMatchedDescription, e));
            }
            return null;
        }
    }
}
