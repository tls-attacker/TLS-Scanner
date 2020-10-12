package de.rub.nds.tlsscanner.clientscanner.dispatcher.exception;

public class DispatchException extends Exception {
    public DispatchException() {
        super();
    }

    public DispatchException(String message) {
        super(message);
    }

    public DispatchException(String message, Throwable cause) {
        super(message, cause);
    }

    public DispatchException(Throwable cause) {
        super(cause);
    }

    protected DispatchException(String message, Throwable cause,
            boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}