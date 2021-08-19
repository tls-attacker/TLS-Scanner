package de.rub.nds.tlsscanner.serverscanner.constants;

public enum CertificateLength {
    TWO(2),
    THREE(3);

    private int length;

    private CertificateLength(int i) {
        this.length = i;
    }

    public int getLength() {
        return length;
    }
}
