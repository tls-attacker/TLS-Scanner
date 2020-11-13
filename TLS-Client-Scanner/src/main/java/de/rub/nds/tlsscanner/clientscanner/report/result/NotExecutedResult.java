/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.report.result;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlTransient;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsscanner.clientscanner.probe.Probe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;

@XmlAccessorType(XmlAccessType.FIELD)
public class NotExecutedResult extends ClientProbeResult {
    private static final Logger LOGGER = LogManager.getLogger();
    @XmlTransient
    private final Class<? extends Probe> probe;
    public final String message;

    public NotExecutedResult(Class<? extends Probe> probe, String message) {
        this.probe = probe;
        this.message = message;
    }

    public static NotExecutedResult UNKNOWN_ERROR(Class<? extends Probe> probe) {
        return new NotExecutedResult(probe, "An unknown error caused this probe to not be executed.");
    }

    public static NotExecutedResult MISSING_DEPENDENT_RESULT(Class<? extends Probe> probe,
            Class<? extends Probe> missingProbe) {
        return new NotExecutedResult(probe,
                "This Probe could not be executed, as it depends on the result of the following probe (which is missing): "
                        + missingProbe.getName());
    }

    @Override
    @SuppressWarnings("squid:S2445")
    // using parameter to synchronize
    public void merge(ClientReport report) {
        synchronized (report) {
            if (!report.hasResult(probe)) {
                report.putResult(probe, this);
            }
        }
    }

}
