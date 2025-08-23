/*
 * Copyright 2014 CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.scriptsecurity.sandbox.whitelists;

import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Implementation of {@link Whitelist} that permits the execution of all code.
 *
 * @author joseross
 */
public class PermitAllWhitelist extends Whitelist {

    @Override
    public boolean permitsMethod(final Method method, final Object receiver, final Object[] args) {
        return true;
    }

    @Override
    public boolean permitsConstructor(final Constructor<?> constructor, final Object[] args) {
        return true;
    }

    @Override
    public boolean permitsStaticMethod(final Method method, final Object[] args) {
        return true;
    }

    @Override
    public boolean permitsFieldGet(final Field field, final Object receiver) {
        return true;
    }

    @Override
    public boolean permitsFieldSet(final Field field, final Object receiver, final Object value) {
        return true;
    }

    @Override
    public boolean permitsStaticFieldGet(final Field field) {
        return true;
    }

    @Override
    public boolean permitsStaticFieldSet(final Field field, final Object value) {
        return true;
    }
}
