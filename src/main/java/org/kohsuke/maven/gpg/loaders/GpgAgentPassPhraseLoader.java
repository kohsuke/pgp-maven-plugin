package org.kohsuke.maven.gpg.loaders;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Structure;
import org.apache.maven.plugin.MojoExecutionException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.codehaus.plexus.component.annotations.Component;
import org.kohsuke.maven.gpg.PassphraseLoader;
import org.kohsuke.maven.gpg.PgpMojo;

import java.io.BufferedReader;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketImpl;
import java.util.Arrays;

/**
 * @author Kohsuke Kawaguchi
 */
@Component(role=PassphraseLoader.class,hint="gpg-agent")
public class GpgAgentPassPhraseLoader extends PassphraseLoader {
    @Override
    public String load(PgpMojo mojo, String specifier) throws IOException, MojoExecutionException {
        String agentInfo = System.getenv("GPG_AGENT_INFO");
        if (agentInfo==null)
            throw new MojoExecutionException("GPG agent is not running. There's no GPG_AGENT_INFO environment variable");

        String[] tokens = agentInfo.split(":"); // socket file:PID:1
        if (tokens.length!=3 || !tokens[2].equals("1"))
            throw new MojoExecutionException("Invalid  GPG_AGENT_INFO: "+agentInfo);

        connect(tokens[0]);

        return null;
    }

    /**
     * Connects to GPG agent.
     */
    private Socket connect(String socketLocation) throws MojoExecutionException, IOException {
        int socket = libc.socket(PF_UNIX,SOCK_STREAM,0);

        sockaddr_un adr = new sockaddr_un();
        adr.sun_family = AF_UNIX;
        byte[] bytes = socketLocation.getBytes();
        System.arraycopy(bytes,0,adr.sun_path,0,bytes.length);
        int len = bytes.length+2/*sizeof(short)*/;

        if (libc.connect(socket,adr,len)!=0)
            throw new MojoExecutionException("Failed to connect to GPG agent at "+ socketLocation);

        try {
            Constructor c = FileDescriptor.class.getDeclaredConstructor(int.class);
            c.setAccessible(true);
            FileDescriptor fd = (FileDescriptor)c.newInstance(socket);
            c = Class.forName("java.net.PlainSocketImpl").getDeclaredConstructor(FileDescriptor.class);
            c.setAccessible(true);
            UnixDomainSocket s = new UnixDomainSocket((SocketImpl) c.newInstance(fd));
            return s;
        } catch (NoSuchMethodException e) {
            throw new Error(e);
        } catch (InstantiationException e) {
            throw new Error(e);
        } catch (IllegalAccessException e) {
            throw new Error(e);
        } catch (InvocationTargetException e) {
            throw new Error(e);
        } catch (ClassNotFoundException e) {
            throw new Error(e);
        } catch (NoSuchFieldException e) {
            throw new Error(e);
        } catch (SocketException e) {
            throw (IOException)new IOException("Failed to talk to GPG agent").initCause(e);
        }
    }

    public String getPassphrase(String socketFile) throws IOException, MojoExecutionException {
        Socket s = connect(socketFile);
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
            expectOK(in);

            String display = System.getenv("DISPLAY");
            if (display!=null) {
                s.getOutputStream().write(("OPTION display=" + display + "\n").getBytes());
                expectOK(in);
            }

            String term = System.getenv("TERM");
            if (term!=null) {
                s.getOutputStream().write(("OPTION ttytype=" + term + "\n").getBytes());
                expectOK(in);
            }

//            try {
//                String tty = libc.ctermid(null);
//                if (tty!=null) {
//                    s.getOutputStream().write(("OPTION ttyname=" + tty + "\n").getBytes());
//                    expectOK(in);
//                }
//            } catch (Error e) {
//                // if we fail to figure out TTY, move on
//            }

            s.getOutputStream().write(
                    "GET_PASSPHRASE pgp-maven-plugin:passphrase1 + Passphrase Enter%20Passphrase%20To%20Sign%20Maven%20Artifact\n".getBytes()
            );
            s.getOutputStream().flush();
            return new String(Hex.decode(expectOK(in).trim()));
        } finally {
            s.close();
        }
    }

    private String expectOK(BufferedReader in) throws IOException {
        String rsp = in.readLine();
        if (!rsp.startsWith("OK"))
                throw new IOException("Expected OK but got this instead: "+rsp);
        return rsp.substring(Math.min(rsp.length(),3));
    }

    private static class UnixDomainSocket extends Socket {
        protected UnixDomainSocket(SocketImpl impl) throws SocketException, NoSuchFieldException, IllegalAccessException {
            super(impl);

            Field f = Socket.class.getDeclaredField("connected");
            f.setAccessible(true);
            f.set(this,true);

            f = Socket.class.getDeclaredField("bound");
            f.setAccessible(true);
            f.set(this,true);
        }
    }

    LIBC libc = (LIBC)Native.loadLibrary(LIBC.class);

    public interface LIBC extends Library {
        int socket(int namespace, int style, int protocol);
        int connect(int socket, sockaddr_un adr, int len);
        String ctermid(String passNull);
    }

    public class sockaddr_un extends Structure {
        public short sun_family;
        public byte[] sun_path = new byte[108];
    }

    private static final int PF_UNIX = 1;
    private static final int AF_UNIX = 1;
    private static final int SOCK_STREAM = 1;

    public static void main(String[] args) throws Exception {
        System.out.println(new GpgAgentPassPhraseLoader().getPassphrase("/tmp/gpg-B8NipE/S.gpg-agent"));
    }
}
