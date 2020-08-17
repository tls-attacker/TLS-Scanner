package de.rub.nds.tlsscanner.clientscanner.probe.runner;

import java.util.concurrent.Callable;

import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public interface IProbeRunner extends Callable<ClientProbeResult> {

}