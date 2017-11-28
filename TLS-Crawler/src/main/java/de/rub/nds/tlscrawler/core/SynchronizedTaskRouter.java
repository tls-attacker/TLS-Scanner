/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.core;

import de.rub.nds.tlscrawler.data.IScanTask;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 * This class implements the synchronization logic to distribute tasks between
 * worker threads.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class SynchronizedTaskRouter {
    private final Object _syncrootTodo = new Object();
    private final Object _syncrootFinished = new Object();

    private List<IScanTask> todo;
    private List<IScanTask> finished;

    public SynchronizedTaskRouter() {
        this.todo = new LinkedList<>();
        this.finished = new LinkedList<>();
    }

    public void addTodo(IScanTask todo) {
        synchronized (_syncrootTodo) {
            this.todo.add(todo);
        }
    }

    public void addTodo(Collection<IScanTask> todo) {
        synchronized (_syncrootTodo) {
            this.todo.addAll(todo);
        }
    }

    public IScanTask getTodo() {
        IScanTask result = null;

        synchronized (_syncrootTodo) {
            if (this.todo.size() > 0) {
                result = this.todo.remove(0);
            }
        }

        return result;
    }

    public int getTodoCount() {
        int result;

        synchronized (_syncrootTodo) {
            result = this.todo.size();
        }

        return result;
    }

    public void addFinished(IScanTask finished) {
        synchronized (_syncrootFinished) {
            this.finished.add(finished);
        }
    }

    public List<IScanTask> getFinished() {
        List<IScanTask> result = new LinkedList<>();

        synchronized (_syncrootFinished) {
            while (!this.finished.isEmpty()) {
                result.add(this.finished.remove(0));
            }
        }

        return result;
    }

    public int getFinishedCount() {
        int result;

        synchronized (_syncrootFinished) {
            result = this.finished.size();
        }

        return result;
    }
}
