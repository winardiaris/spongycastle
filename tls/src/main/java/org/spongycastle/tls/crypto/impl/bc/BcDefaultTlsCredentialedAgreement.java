package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.math.BigInteger;

import org.spongycastle.crypto.BasicAgreement;
import org.spongycastle.crypto.agreement.DHBasicAgreement;
import org.spongycastle.crypto.agreement.ECDHBasicAgreement;
import org.spongycastle.crypto.params.AsymmetricKeyParameter;
import org.spongycastle.crypto.params.DHPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.tls.Certificate;
import org.spongycastle.tls.TlsCredentialedAgreement;
import org.spongycastle.tls.crypto.TlsCertificate;
import org.spongycastle.tls.crypto.TlsSecret;
import org.spongycastle.util.BigIntegers;

/**
 * Credentialed class generating agreed secrets from a peer's public key for our end of the TLS connection using the BC light-weight API.
 */
public class BcDefaultTlsCredentialedAgreement
    implements TlsCredentialedAgreement
{
    protected TlsCredentialedAgreement agreementCredentials;

    public BcDefaultTlsCredentialedAgreement(BcTlsCrypto crypto, Certificate certificate, AsymmetricKeyParameter privateKey)
    {
        if (crypto == null)
        {
            throw new IllegalArgumentException("'crypto' cannot be null");
        }
        if (certificate == null)
        {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }
        if (certificate.isEmpty())
        {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        }
        if (privateKey == null)
        {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        }
        if (!privateKey.isPrivate())
        {
            throw new IllegalArgumentException("'privateKey' must be private");
        }

        if (privateKey instanceof DHPrivateKeyParameters)
        {
            agreementCredentials = new DHCredentialedAgreement(crypto, privateKey, certificate);
        }
        else if (privateKey instanceof ECPrivateKeyParameters)
        {
            agreementCredentials = new ECCredentialedAgreement(crypto, privateKey, certificate);
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: "
                + privateKey.getClass().getName());
        }
    }

    public Certificate getCertificate()
    {
        return agreementCredentials.getCertificate();
    }

    public TlsSecret generateAgreement(TlsCertificate peerCertificate)
        throws IOException
    {
        return agreementCredentials.generateAgreement(peerCertificate);
    }

    private class DHCredentialedAgreement
        implements TlsCredentialedAgreement
    {
        private final Certificate certificate;
        private final BcTlsCrypto crypto;
        protected AsymmetricKeyParameter privateKey;

        protected BasicAgreement basicAgreement = new DHBasicAgreement();

        public DHCredentialedAgreement(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey, Certificate certificate)
        {
            this.crypto = crypto;
            this.privateKey = privateKey;
            this.certificate = certificate;
        }

        public TlsSecret generateAgreement(TlsCertificate peerCertificate)
            throws IOException
        {
            TlsCertificate localCert = certificate.getCertificateAt(0);
            AsymmetricKeyParameter peerPublicKey = BcTlsCertificate.convert(crypto, localCert).getPublicKey();
            basicAgreement.init(privateKey);
            BigInteger agreementValue = basicAgreement.calculateAgreement(peerPublicKey);
            return crypto.adoptLocalSecret(BigIntegers.asUnsignedByteArray(agreementValue));
        }

        public Certificate getCertificate()
        {
            return certificate;
        }
    }

    private class ECCredentialedAgreement
        implements TlsCredentialedAgreement
    {
        private final Certificate certificate;
        private final BcTlsCrypto crypto;
        private final AsymmetricKeyParameter privateKey;

        protected BasicAgreement basicAgreement = new ECDHBasicAgreement();

        public ECCredentialedAgreement(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey, Certificate certificate)
        {
            this.crypto = crypto;
            this.privateKey = privateKey;
            this.certificate = certificate;
        }

        public TlsSecret generateAgreement(TlsCertificate peerCertificate)
            throws IOException
        {
            TlsCertificate localCert = certificate.getCertificateAt(0);
            AsymmetricKeyParameter peerPublicKey = BcTlsCertificate.convert(crypto, localCert).getPublicKey();
            basicAgreement.init(privateKey);
            BigInteger agreementValue = basicAgreement.calculateAgreement(peerPublicKey);
            return crypto.adoptLocalSecret(BigIntegers.asUnsignedByteArray(basicAgreement.getFieldSize(), agreementValue));
        }

        public Certificate getCertificate()
        {
            return certificate;
        }
    }
}
