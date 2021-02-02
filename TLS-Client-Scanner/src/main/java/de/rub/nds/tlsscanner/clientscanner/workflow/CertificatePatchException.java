package de.rub.nds.tlsscanner.clientscanner.workflow;

import de.rub.nds.tlsscanner.clientscanner.dispatcher.exception.DispatchException;

public class CertificatePatchException extends DispatchException {

    public CertificatePatchException(Exception e) {
        super(e);
    }
}
