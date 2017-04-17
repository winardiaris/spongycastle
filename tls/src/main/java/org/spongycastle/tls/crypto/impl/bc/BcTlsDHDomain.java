package org.spongycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.math.BigInteger;

import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.agreement.DHBasicAgreement;
import org.spongycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.spongycastle.crypto.params.DHKeyGenerationParameters;
import org.spongycastle.crypto.params.DHParameters;
import org.spongycastle.crypto.params.DHPrivateKeyParameters;
import org.spongycastle.crypto.params.DHPublicKeyParameters;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.TlsFatalAlert;
import org.spongycastle.tls.crypto.TlsAgreement;
import org.spongycastle.tls.crypto.TlsDHConfig;
import org.spongycastle.tls.crypto.TlsDHDomain;
import org.spongycastle.util.BigIntegers;

/**
 * BC light-weight support class for Diffie-Hellman key pair generation and key agreement over a specified Diffie-Hellman configuration.
 */
public class BcTlsDHDomain implements TlsDHDomain
{
    protected BcTlsCrypto crypto;
    protected TlsDHConfig dhConfig;
    protected DHParameters dhDomain;

    public BcTlsDHDomain(BcTlsCrypto crypto, TlsDHConfig dhConfig)
    {
        this.crypto = crypto;
        this.dhConfig = dhConfig;
        this.dhDomain = getParameters(dhConfig);
    }

    public byte[] calculateDHAgreement(DHPublicKeyParameters publicKey, DHPrivateKeyParameters privateKey)
    {
        DHBasicAgreement basicAgreement = new DHBasicAgreement();
        basicAgreement.init(privateKey);
        BigInteger agreementValue = basicAgreement.calculateAgreement(publicKey);

        /*
         * RFC 5246 8.1.2. Leading bytes of Z that contain all zero bits are stripped before it is
         * used as the pre_master_secret.
         */
        return BigIntegers.asUnsignedByteArray(agreementValue);
    }

    public TlsAgreement createDH()
    {
        return new BcTlsDH(this);
    }

    public static BigInteger decodeParameter(byte[] encoding) throws IOException
    {
        return new BigInteger(1, encoding);
    }

    public DHPublicKeyParameters decodePublicKey(byte[] encoding) throws IOException
    {
        try
        {
            BigInteger y = decodeParameter(encoding);

            // TODO Check RFCs for any validation that could/should be done here

            return new DHPublicKeyParameters(y, dhDomain);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }
    }

    public byte[] encodeParameter(BigInteger x) throws IOException
    {
        return BigIntegers.asUnsignedByteArray(x);
    }

    public byte[] encodePublicKey(DHPublicKeyParameters publicKey) throws IOException
    {
        return encodeParameter(publicKey.getY());
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        DHBasicKeyPairGenerator keyPairGenerator = new DHBasicKeyPairGenerator();
        keyPairGenerator.init(new DHKeyGenerationParameters(crypto.getSecureRandom(), dhDomain));
        return keyPairGenerator.generateKeyPair();
    }

    public BcTlsCrypto getCrypto()
    {
        return crypto;
    }

    public DHParameters getParameters(TlsDHConfig dhConfig)
    {
        // TODO There's a draft RFC for negotiated (named) groups

        BigInteger[] pg = dhConfig.getExplicitPG();
        if (pg != null)
        {
            return new DHParameters(pg[0], pg[1]);
        }

        throw new IllegalStateException("No DH configuration provided");
    }
}
