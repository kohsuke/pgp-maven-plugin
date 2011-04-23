package org.kohsuke.maven.gpg.loaders;

import org.apache.maven.plugin.MojoExecutionException;
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.util.FileUtils;
import org.kohsuke.maven.gpg.PassphraseLoader;
import org.kohsuke.maven.gpg.PgpMojo;

import java.io.File;
import java.io.IOException;

/**
 * Loads a pass phrase from a file.
 *
 * @author Kohsuke Kawaguchi
 */
@Component(role=PassphraseLoader.class,hint="file")
public class FilePassPhraseLoader extends PassphraseLoader {
    @Override
    public String load(PgpMojo mojo, String specifier) throws IOException, MojoExecutionException {
        File f = new File(specifier);
        if (!f.exists())
            throw new MojoExecutionException("No such file exists: "+specifier);
        return FileUtils.fileRead(f);
    }
}
