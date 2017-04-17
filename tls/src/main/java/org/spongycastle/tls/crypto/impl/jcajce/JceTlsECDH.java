package org.spongycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import org.spongycastle.tls.crypto.TlsAgreement;
import org.spongycastle.tls.crypto.TlsSecret;

/**
 * Support class for ephemeral Elliptic Curve Diffie-Hellman using the JCE.
 */
public class JceTlsECDH
    implements TlsAgreement
{
    protected JceTlsECDomain domain;
    protected KeyPair localKeyPair;
    protected ECPublicKey peerPublicKey;

    public JceTlsECDH(JceTlsECDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.localKeyPair = domain.generateKeyPair();
        return domain.encodePublicKey((ECPublicKey)localKeyPair.getPublic());
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        this.peerPublicKey = domain.decodePublicKey(peerValue);
    }

    public TlsSecret calculateSecret() throws IOException
    {
        try
        {
            byte[] data = domain.calculateECDHAgreement(peerPublicKey, (ECPrivateKey)localKeyPair.getPrivate());
            return domain.getCrypto().adoptLocalSecret(data);
        }
        catch (GeneralSecurityException e)
        {
            throw new IOException("cannot calculate secret", e);
        }
    }
}
