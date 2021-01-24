/**
 * TLS Crawler
 * <p>
 * Licensed under Apache 2.0
 * <p>
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.ScanTask;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import lombok.extern.log4j.Log4j2;

/**
 * This class implements the synchronization logic to distribute tasks between
 * worker threads.
 *
 * @author janis.fliegenschmidt@rub.de
 */
@Log4j2
public class SynchronizedTaskRouter {

    private final Object _syncrootTodo = new Object();
    private final Object _syncrootFinished = new Object();

    private final List<ScanTask> todo;
    private final List<ScanTask> finished;

    public SynchronizedTaskRouter() {
        this.todo = new LinkedList<>();
        this.finished = new LinkedList<>();
    }

    public void addTodo(ScanTask todo) {
        log.trace("addTodo()");

        synchronized (_syncrootTodo) {
            this.todo.add(todo);
        }
    }

    public void addTodo(Collection<ScanTask> todo) {
        log.trace("addTodo()");

        synchronized (_syncrootTodo) {
            this.todo.addAll(todo);
        }
    }

    public ScanTask getTodo() {
        log.trace("getTodo()");

        ScanTask result = null;
        synchronized (_syncrootTodo) {
            if (this.todo.size() > 0) {
                result = this.todo.remove(0);
            }
        }

        return result;
    }

    public int getTodoCount() {
        log.trace("getTodoCount()");

        int result;
        synchronized (_syncrootTodo) {
            result = this.todo.size();
        }

        return result;
    }

    public void addFinished(ScanTask finished) {
        log.trace("addFinished()");

        synchronized (_syncrootFinished) {
            this.finished.add(finished);
        }
    }

    public List<ScanTask> getFinished() {
        log.trace("getFinished()");

        List<ScanTask> result = new LinkedList<>();
        synchronized (_syncrootFinished) {
            while (!this.finished.isEmpty()) {
                result.add(this.finished.remove(0));
            }
        }

        return result;
    }

    public int getFinishedCount() {
        log.trace("getFinishedCount()");

        int result;
        synchronized (_syncrootFinished) {
            result = this.finished.size();
        }

        return result;
    }
}
