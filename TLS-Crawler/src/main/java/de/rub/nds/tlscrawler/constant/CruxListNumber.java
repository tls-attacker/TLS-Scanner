package de.rub.nds.tlscrawler.constant;

public enum CruxListNumber {
    TOP_1k(1000),
    TOP_5K(5000),
    TOP_10K(10000),
    TOP_50K(50000),
    TOP_100K(100000),
    TOP_500k(500000),
    TOP_1M(1000000);

    private final int number;

    CruxListNumber(int number) {
        this.number = number;
    }

    public int getNumber() {
        return number;
    }
}
