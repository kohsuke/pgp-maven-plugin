package org.kohsuke.maven.gpg;

import org.apache.maven.plugin.MojoExecutionException;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kohsuke Kawaguchi
 */
public abstract class SecretKeyLoader {
    public abstract PGPSecretKey load(PgpMojo mojo, String specifier) throws IOException, MojoExecutionException;

    protected final Map<String,String> parseQueryParameters(String specifier) {
        Map<String,String> opts = new HashMap<String, String>();
        for (String token : specifier.split("&")) {
            int idx = token.indexOf('=');
            if (idx<0)  opts.put(token,"");
            else        opts.put(token.substring(0,idx),token.substring(idx+1));
        }
        return opts;
    }
}
