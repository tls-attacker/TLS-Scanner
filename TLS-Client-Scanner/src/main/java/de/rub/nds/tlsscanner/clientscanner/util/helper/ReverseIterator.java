package de.rub.nds.tlsscanner.clientscanner.util.helper;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

public class ReverseIterator<T> implements Iterator<T>, Iterable<T> {

    private final List<T> iterable;
    private int position;

    public ReverseIterator(List<T> iterable) {
        this.iterable = iterable;
        this.position = iterable.size() - 1;
    }

    public ReverseIterator(T[] iterable) {
        this(Arrays.asList(iterable));
    }

    @Override
    public Iterator<T> iterator() {
        return this;
    }

    @Override
    public boolean hasNext() {
        return position >= 0;
    }

    @Override
    public T next() {
        return iterable.get(position--);
    }

    @Override
    public void remove() {
        throw new UnsupportedOperationException();
    }

}