/*
 * Copyright (C) 2007-2025 Crafter Software Corporation. All Rights Reserved.
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

import static org.junit.jupiter.api.Assertions.assertThrows;

import groovy.lang.Binding;
import groovy.lang.GroovyClassLoader;
import groovy.util.GroovyScriptEngine;
import groovy.util.ResourceException;
import groovy.util.ScriptException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.jenkinsci.plugins.scriptsecurity.sandbox.Whitelist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.blacklists.Blacklist;
import org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SandboxInterceptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.kohsuke.groovy.sandbox.SandboxTransformer;

class CompositeWhitelistTest {

    private static final String EMPTY_WHITELIST = "groovy/whitelist-empty";

    private static final String WHITELIST = "groovy/whitelist";

    private static final String BLACKLIST = "groovy/blacklist";

    private static final String SCRIPTS_PATH = "src/test/resources/groovy/scripts";

    private static final String INVALID_SCRIPT = "invalid.groovy";

    private static final String MULTIPLE_OPS_SCRIPT = "multiple-ops.groovy";

    private GroovyScriptEngine scriptEngine;

    private SandboxInterceptor sandboxInterceptorEmptyWhitelist;

    private SandboxInterceptor sandboxInterceptor;

    private GroovyScriptEngine setUpGroovyScriptEngine() throws IOException {
        CompilerConfiguration compilerConfig = new CompilerConfiguration();
        compilerConfig.addCompilationCustomizers(new SandboxTransformer());
        return new GroovyScriptEngine(SCRIPTS_PATH, new GroovyClassLoader(getClass().getClassLoader(), compilerConfig));
    }

    private SandboxInterceptor setUpSandboxInterceptor(final String whitelist) throws IOException {
        ClassLoader loader = getClass().getClassLoader();
        Whitelist whitelist1 = new Blacklist(new InputStreamReader(loader.getResourceAsStream(BLACKLIST)));
        Whitelist whitelist2 = new StaticWhitelist(new InputStreamReader(loader.getResourceAsStream(whitelist)));

        return new SandboxInterceptor(new CompositeWhitelist(List.of(whitelist1, whitelist2)));
    }

    @BeforeEach
    void setup() throws IOException {
        scriptEngine = setUpGroovyScriptEngine();
        sandboxInterceptorEmptyWhitelist = setUpSandboxInterceptor(EMPTY_WHITELIST);
        sandboxInterceptor = setUpSandboxInterceptor(WHITELIST);
    }

    @Test
    void testRestrictedCall() {
        sandboxInterceptorEmptyWhitelist.register();

        assertThrows(
                SecurityException.class,
                () -> scriptEngine.run(INVALID_SCRIPT, new Binding()),
                INVALID_SCRIPT + " contains unsupported operations");

        sandboxInterceptorEmptyWhitelist.unregister();
    }

    @Test
    void testAllowedCall() throws ScriptException, ResourceException {
        sandboxInterceptor.register();
        scriptEngine.run(INVALID_SCRIPT, new Binding());

        sandboxInterceptor.unregister();
    }

    @Test
    void testMultipleRestrictedCalls() {
        sandboxInterceptorEmptyWhitelist.register();
        assertThrows(
                SecurityException.class,
                () -> scriptEngine.run(MULTIPLE_OPS_SCRIPT, new Binding()),
                MULTIPLE_OPS_SCRIPT + " contains unsupported operations");
        sandboxInterceptorEmptyWhitelist.unregister();

        sandboxInterceptor.register();
        assertThrows(
                SecurityException.class,
                () -> scriptEngine.run(MULTIPLE_OPS_SCRIPT, new Binding()),
                MULTIPLE_OPS_SCRIPT + " contains non-whitelisted operations. They should fail even if accepted"
                + " by the blacklist");
        sandboxInterceptor.unregister();
    }
}
