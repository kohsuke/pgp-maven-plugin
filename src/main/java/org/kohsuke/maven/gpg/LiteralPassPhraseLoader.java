package org.kohsuke.maven.gpg;

import org.apache.maven.plugin.MojoExecutionException;
import org.codehaus.plexus.component.annotations.Component;

import java.io.IOException;

/**
 * Specifies a pass phrase directly as literal.
 * 
 * @author Kohsuke Kawaguchi
 */
@Component(role=PassphraseLoader.class,hint="literal")
public class LiteralPassPhraseLoader extends PassphraseLoader {
    @Override
    public String load(PgpMojo mojo, String specifier) throws IOException, MojoExecutionException {
        return specifier;
    }
}
