package org.kohsuke.maven.pgp;

/*
 * Copyright 2001-2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.artifact.versioning.VersionRange;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.codehaus.plexus.PlexusContainer;
import org.codehaus.plexus.component.repository.exception.ComponentLookupException;
import org.codehaus.plexus.util.FileUtils;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

/**
 * Signs the artifacts.
 *
 * @goal sign
 * @phase verify
 */
public class PgpMojo extends AbstractMojo
{
    /**
     * How to retrieve the secret key?
     *
     * @parameter expression="${pgp.secretkey}
     */
    public String secretkey;

    /**
     * String that indicates where to retrieve the secret key pass phrase from.
     *
     * @parameter expression="${pgp.passphrase}
     */
    public String passphrase;

    /**
     * Skip the PGP signing.
     *
     * @parameter expression="${pgp.skip}" default-value="false"
     */
    private boolean skip;

    /**
     *
     * 
     * @parameter default-value="${project}"
     * @required
     * @readonly
     */
    public MavenProject project;

    /**
     *
     * @component
     * @required
     * @readonly
     */
    public MavenProjectHelper projectHelper;

    /**
     * @component
     * @required
     * @readonly
     */
    public PlexusContainer container;

    /**
     *
     * @parameter default-value="${project.build.directory}"
     */
    private File outputDirectory;


    public void execute() throws MojoExecutionException {
        if (skip)   return;

        // capture the attached artifacts to sign before we start attaching our own stuff
        List<Artifact> attached = new ArrayList<Artifact>((List<Artifact>)project.getAttachedArtifacts());

        PGPSecretKey secretKey = loadSecretKey();
        Signer signer = new Signer(secretKey,loadPassPhrase(secretKey).toCharArray());

        if ( !"pom".equals( project.getPackaging() ) )
            sign(signer,project.getArtifact());

        {// sign POM
            File pomToSign = new File( project.getBuild().getDirectory(), project.getBuild().getFinalName() + ".pom" );

            try {
                FileUtils.copyFile(project.getFile(), pomToSign);
            } catch ( IOException e ) {
                throw new MojoExecutionException( "Error copying POM for signing.", e );
            }

            getLog().debug( "Generating signature for " + pomToSign );

            // fake just enough Artifact for the sign method
            DefaultArtifact a = new DefaultArtifact(project.getGroupId(), project.getArtifactId(),
                    VersionRange.createFromVersion(project.getVersion()), null, "pom", null,
                    new DefaultArtifactHandler("pom"));
            a.setFile(pomToSign);

            sign(signer,a);
        }

        for (Artifact a : attached)
            sign(signer,a);
    }

    /**
     * From {@link #secretkey}, load the key pair.
     */
    public PGPSecretKey loadSecretKey() throws MojoExecutionException {
        if (secretkey==null)
            secretkey = System.getenv("PGP_SECRETKEY");
        if (secretkey==null)
            throw new MojoExecutionException("No PGP secret key is configured. Either do so in POM, or via -Dpgp.secretkey, or the PGP_SECRETKEY environment variable");

        int head = secretkey.indexOf(':');
        if (head<0)
            throw new MojoExecutionException("Invalid secret key string. It needs to start with a scheme like 'FOO:': "+secretkey);

        String scheme = secretkey.substring(0, head);
        try {
            SecretKeyLoader kfl = (SecretKeyLoader)container.lookup(SecretKeyLoader.class.getName(), scheme);
            return  kfl.load(this, secretkey.substring(head+1));
        } catch (ComponentLookupException e) {
            throw new MojoExecutionException("Invalid secret key scheme '"+scheme+"'. If this is your custom scheme, perhaps you forgot to specify it in <dependency> to this plugin?",e);
         } catch (IOException e) {
            throw new MojoExecutionException("Failed to load key from "+secretkey,e);
        }
    }

    /**
     * From {@link #passphrase}, load the passphrase.
     */
    public String loadPassPhrase(PGPSecretKey key) throws MojoExecutionException {
        if (passphrase==null)
            passphrase = System.getenv("PGP_PASSPHRASE");
        if (passphrase==null)
            throw new MojoExecutionException("No PGP passphrase is configured. Either do so in POM, or via -Dpgp.passphrase, or the PGP_PASSPHRASE environment variable");

        int head = passphrase.indexOf(':');
        if (head<0)
            throw new MojoExecutionException("Invalid passphrase string. It needs to start with a scheme like 'FOO:': "+passphrase);

        String scheme = passphrase.substring(0, head);
        try {
            PassphraseLoader pfl = (PassphraseLoader)container.lookup(PassphraseLoader.class.getName(), scheme);
            return  pfl.load(this, key, passphrase.substring(head+1));
        } catch (ComponentLookupException e) {
            throw new MojoExecutionException("Invalid pass phrase scheme '"+scheme+"'. If this is your custom scheme, perhaps you forgot to specify it in <dependency> to this plugin?",e);
         } catch (IOException e) {
            throw new MojoExecutionException("Failed to load passphrase from "+passphrase,e);
        }
    }

    /**
     * Sign and attach the signaature to the build.
     */
    protected void sign(Signer signer, Artifact a) throws MojoExecutionException {
        String name = a.getGroupId() + "-" + a.getArtifactId();
        if (a.getClassifier()!=null)
            name += '-'+a.getClassifier();
        name += '.'+a.getArtifactHandler().getExtension();
        name += ".asc";

        File signature = new File(outputDirectory,name);

        try {
            signer.sign(a.getFile(),signature);
        } catch (PGPException e) {
            throw new MojoExecutionException("Failed to sign "+a.getFile(),e);
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to sign "+a.getFile(),e);
        } catch (GeneralSecurityException e) {
            throw new MojoExecutionException("Failed to sign "+a.getFile(),e);
        }

        projectHelper.attachArtifact( project, a.getArtifactHandler().getExtension() + ".asc",
                                      a.getClassifier(), signature );

    }
}
