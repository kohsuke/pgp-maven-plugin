package org.kohsuke.maven.gpg.loaders;

import org.apache.maven.plugin.MojoExecutionException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.util.FileUtils;
import org.kohsuke.maven.gpg.PassphraseLoader;
import org.kohsuke.maven.gpg.PgpMojo;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.Iterator;

/**
 * Loads a pass phrase from a file.
 *
 * @author Kohsuke Kawaguchi
 */
@Component(role=PassphraseLoader.class,hint="file")
public class FilePassPhraseLoader extends PassphraseLoader {
    @Override
    public String load(PgpMojo mojo, PGPSecretKey secretKey, String specifier) throws IOException, MojoExecutionException {
        File f = new File(specifier.replace('|',':'));
        if (!f.exists())
            throw new MojoExecutionException("No such file exists: "+specifier);
        return FileUtils.fileRead(f).trim();
    }
}
