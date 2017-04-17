package org.spongycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Vector;

import org.spongycastle.asn1.x509.Certificate;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.AlertLevel;
import org.spongycastle.tls.CertificateRequest;
import org.spongycastle.tls.ClientCertificateType;
import org.spongycastle.tls.DefaultTlsServer;
import org.spongycastle.tls.ProtocolVersion;
import org.spongycastle.tls.SignatureAlgorithm;
import org.spongycastle.tls.TlsCredentialedDecryptor;
import org.spongycastle.tls.TlsCredentialedSigner;
import org.spongycastle.tls.TlsFatalAlert;
import org.spongycastle.tls.TlsUtils;
import org.spongycastle.tls.crypto.TlsCertificate;
import org.spongycastle.tls.crypto.impl.bc.BcTlsCrypto;

class MockTlsServer
    extends DefaultTlsServer
{
    MockTlsServer()
    {
        super(new BcTlsCrypto(new SecureRandom()));
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS server raised alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
        if (message != null)
        {
            out.println("> " + message);
        }
        if (cause != null)
        {
            cause.printStackTrace(out);
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS server received alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        System.out.println("TLS server negotiated " + serverVersion);

        return serverVersion;
    }

    public CertificateRequest getCertificateRequest() throws IOException
    {
        short[] certificateTypes = new short[]{ ClientCertificateType.rsa_sign,
            ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign };

        Vector serverSigAlgs = null;
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(serverVersion))
        {
            serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms();
        }

        Vector certificateAuthorities = new Vector();
        certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca.pem").getSubject());

        return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
    }

    public void notifyClientCertificate(org.spongycastle.tls.Certificate clientCertificate)
        throws IOException
    {
        TlsCertificate[] chain = clientCertificate.getCertificateList();

        System.out.println("TLS server received client certificate chain of length " + chain.length);
        for (int i = 0; i != chain.length; i++)
        {
            Certificate entry = Certificate.getInstance(chain[i].getEncoded());
            // TODO Create fingerprint based on certificate signature algorithm digest
            System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                + entry.getSubject() + ")");
        }

        boolean isEmpty = (clientCertificate == null || clientCertificate.isEmpty());
        if (!isEmpty && !TlsTestUtils.isCertificateOneOf(context.getCrypto(), chain[0],
            new String[]{ "x509-client.pem", "x509-client-dsa.pem", "x509-client-ecdsa.pem"}))
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }
    }

    protected TlsCredentialedDecryptor getRSAEncryptionCredentials()
        throws IOException
    {
        return TlsTestUtils.loadEncryptionCredentials(context, new String[]{"x509-server.pem", "x509-ca.pem"},
            "x509-server-key.pem");
    }

    protected TlsCredentialedSigner getRSASignerCredentials() throws IOException
    {
        return TlsTestUtils.loadSignerCredentials(context, supportedSignatureAlgorithms, SignatureAlgorithm.rsa,
            "x509-server.pem", "x509-server-key.pem");
    }
}