package org.kohsuke.maven.gpg;

import org.apache.maven.plugin.MojoExecutionException;

import java.io.IOException;

/**
 * @author Kohsuke Kawaguchi
 */
public abstract class PassphraseLoader {
    public abstract String load(PgpMojo mojo, String specifier) throws IOException, MojoExecutionException;
}
