package org.spongycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Iterator;

import org.spongycastle.asn1.nist.NISTNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.ECNamedDomainParameters;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPEncryptedData;
import org.spongycastle.openpgp.PGPKeyPair;
import org.spongycastle.openpgp.PGPKeyRingGenerator;
import org.spongycastle.openpgp.PGPPrivateKey;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPSecretKey;
import org.spongycastle.openpgp.PGPSecretKeyRing;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.PGPSignatureGenerator;
import org.spongycastle.openpgp.PGPUtil;
import org.spongycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.spongycastle.openpgp.operator.PGPDigestCalculator;
import org.spongycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.spongycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.spongycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.spongycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.spongycastle.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.test.SimpleTest;

public class PGPECDSATest
    extends SimpleTest
{
    byte[] testPubKey =
        Base64.decode(
            "mFIEUb4HqBMIKoZIzj0DAQcCAwSQynmjwsGJHYJakAEVYxrm3tt/1h8g9Uksx32J" +
            "zG/ZH4RwaD0PbjzEe5EVBmCwSErRZxt/5AxXa0TEHWjya8FetDVFQ0RTQSAoS2V5" +
            "IGlzIDI1NiBiaXRzIGxvbmcpIDx0ZXN0LmVjZHNhQGV4YW1wbGUuY29tPoh6BBMT" +
            "CAAiBQJRvgeoAhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRDqO46kgPLi" +
            "vN1hAP4n0UApR36ziS5D8KUt7wEpBujQE4G3+efATJ+DMmY/SgEA+wbdDynFf/V8" +
            "pQs0+FtCYQ9schzIur+peRvol7OrNnc=");

    byte[] testPrivKey =
        Base64.decode(
            "lKUEUb4HqBMIKoZIzj0DAQcCAwSQynmjwsGJHYJakAEVYxrm3tt/1h8g9Uksx32J" +
            "zG/ZH4RwaD0PbjzEe5EVBmCwSErRZxt/5AxXa0TEHWjya8Fe/gcDAqTWSUiFpEno" +
            "1n8izmLaWTy8GYw5/lK4R2t6D347YGgTtIiXfoNPOcosmU+3OibyTm2hc/WyG4fL" +
            "a0nxFtj02j0Bt/Fw0N4VCKJwKL/QJT+0NUVDRFNBIChLZXkgaXMgMjU2IGJpdHMg" +
            "bG9uZykgPHRlc3QuZWNkc2FAZXhhbXBsZS5jb20+iHoEExMIACIFAlG+B6gCGwMG" +
            "CwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEOo7jqSA8uK83WEA/ifRQClHfrOJ" +
            "LkPwpS3vASkG6NATgbf558BMn4MyZj9KAQD7Bt0PKcV/9XylCzT4W0JhD2xyHMi6" +
            "v6l5G+iXs6s2dw==");

    char[] testPasswd = "test".toCharArray();

    byte[] sExprKey =
        Base64.decode(
            "KDIxOnByb3RlY3RlZC1wcml2YXRlLWtleSgzOmVjYyg1OmN1cnZlMTU6YnJh"
                + "aW5wb29sUDM4NHIxKSgxOnE5NzoEi29XCqkugtlRvONnpAVMQgfecL+Gk86O"
                + "t8LnUizfHG2TqRrtqlMg1DdU8Z8dJWmhJG84IUOURCyjt8nE4BeeCfRIbTU5"
                + "7CB13OqveBdNIRfK45UQnxHLO2MPVXf4GMdtKSg5OnByb3RlY3RlZDI1Om9w"
                + "ZW5wZ3AtczJrMy1zaGExLWFlcy1jYmMoKDQ6c2hhMTg6itLEzGV4Cfg4OjEy"
                + "OTA1NDcyKTE2OgxmufENKFTZUB72+X7AwkgpMTEyOvMWNLZgaGdlTN8XCxa6"
                + "8ia0Xqqb9RvHgTh+iBf0RgY5Tx5hqO9fHOi76LTBMfxs9VC4f1rTketjEUKR"
                + "f5amKb8lrJ67kKEsny4oRtP9ejkNzcvHFqRdxmHyL10ui8M8rJN9OU8ArqWf"
                + "g22dTcKu02cpKDEyOnByb3RlY3RlZC1hdDE1OjIwMTQwNjA4VDE2MDg1MCkp"
                + "KQ==");

    private void generateAndSign()
        throws Exception
    {
        KeyPairGenerator        keyGen = KeyPairGenerator.getInstance("ECDSA", "SC");

        keyGen.initialize(new ECGenParameterSpec("P-256"));

        KeyPair kpSign = keyGen.generateKeyPair();

        PGPKeyPair ecdsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.ECDSA, kpSign, new Date());

        //
        // try a signature
        //
        PGPSignatureGenerator signGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PGPPublicKey.ECDSA, HashAlgorithmTags.SHA256).setProvider("SC"));

        signGen.init(PGPSignature.BINARY_DOCUMENT, ecdsaKeyPair.getPrivateKey());

        signGen.update("hello world!".getBytes());

        PGPSignature sig = signGen.generate();

        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("SC"), ecdsaKeyPair.getPublicKey());

        sig.update("hello world!".getBytes());

        if (!sig.verify())
        {
            fail("signature failed to verify!");
        }

        //
        // generate a key ring
        //
        char[] passPhrase = "test".toCharArray();
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, ecdsaKeyPair,
                 "test@bouncycastle.org", sha1Calc, null, null, new JcaPGPContentSignerBuilder(ecdsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1).setProvider("SC"), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("SC").build(passPhrase));

        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();

        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

        KeyFingerPrintCalculator fingerCalc = new JcaKeyFingerprintCalculator();

        PGPPublicKeyRing pubRingEnc = new PGPPublicKeyRing(pubRing.getEncoded(), fingerCalc);

        if (!Arrays.areEqual(pubRing.getEncoded(), pubRingEnc.getEncoded()))
        {
            fail("public key ring encoding failed");
        }

        PGPSecretKeyRing secRingEnc = new PGPSecretKeyRing(secRing.getEncoded(), fingerCalc);

        if (!Arrays.areEqual(secRing.getEncoded(), secRingEnc.getEncoded()))
        {
            fail("secret key ring encoding failed");
        }


        //
        // try a signature using encoded key
        //
        signGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PGPPublicKey.ECDSA, HashAlgorithmTags.SHA256).setProvider("SC"));

        signGen.init(PGPSignature.BINARY_DOCUMENT, secRing.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("SC").build(passPhrase)));

        signGen.update("hello world!".getBytes());

        sig = signGen.generate();

        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("SC"), secRing.getSecretKey().getPublicKey());

        sig.update("hello world!".getBytes());

        if (!sig.verify())
        {
            fail("re-encoded signature failed to verify!");
        }
    }

    private void generateAndSignBC()
        throws Exception
    {
        ECKeyPairGenerator keyGen = new ECKeyPairGenerator();

        X9ECParameters x9ECParameters = NISTNamedCurves.getByName("P-256");
        keyGen.init(new ECKeyGenerationParameters(new ECNamedDomainParameters(NISTNamedCurves.getOID("P-256"), x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN()), new SecureRandom()));

        AsymmetricCipherKeyPair kpEnc = keyGen.generateKeyPair();

        PGPKeyPair ecdsaKeyPair = new BcPGPKeyPair(PGPPublicKey.ECDSA, kpEnc, new Date());

        //
        // try a signature
        //
        PGPSignatureGenerator signGen = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PGPPublicKey.ECDSA, HashAlgorithmTags.SHA256));

        signGen.init(PGPSignature.BINARY_DOCUMENT, ecdsaKeyPair.getPrivateKey());

        signGen.update("hello world!".getBytes());

        PGPSignature sig = signGen.generate();

        sig.init(new BcPGPContentVerifierBuilderProvider(), ecdsaKeyPair.getPublicKey());

        sig.update("hello world!".getBytes());

        if (!sig.verify())
        {
            fail("signature failed to verify!");
        }

        //
        // generate a key ring
        //
        char[] passPhrase = "test".toCharArray();
        PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, ecdsaKeyPair,
                 "test@bouncycastle.org", sha1Calc, null, null, new BcPGPContentSignerBuilder(ecdsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("SC").build(passPhrase));

        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();

        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

        KeyFingerPrintCalculator fingerCalc = new BcKeyFingerprintCalculator();

        PGPPublicKeyRing pubRingEnc = new PGPPublicKeyRing(pubRing.getEncoded(), fingerCalc);

        if (!Arrays.areEqual(pubRing.getEncoded(), pubRingEnc.getEncoded()))
        {
            fail("public key ring encoding failed");
        }

        PGPSecretKeyRing secRingEnc = new PGPSecretKeyRing(secRing.getEncoded(), fingerCalc);

        if (!Arrays.areEqual(secRing.getEncoded(), secRingEnc.getEncoded()))
        {
            fail("secret key ring encoding failed");
        }


        //
        // try a signature using encoded key
        //
        signGen = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PGPPublicKey.ECDSA, HashAlgorithmTags.SHA256));

        signGen.init(PGPSignature.BINARY_DOCUMENT, secRing.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase)));

        signGen.update("hello world!".getBytes());

        sig = signGen.generate();

        sig.init(new BcPGPContentVerifierBuilderProvider(), secRing.getSecretKey().getPublicKey());

        sig.update("hello world!".getBytes());

        if (!sig.verify())
        {
            fail("re-encoded signature failed to verify!");
        }
    }

    public void performTest()
        throws Exception
    {
        //
        // Read the public key
        //
        PGPPublicKeyRing        pubKeyRing = new PGPPublicKeyRing(testPubKey, new JcaKeyFingerprintCalculator());

        for (Iterator it = pubKeyRing.getPublicKey().getSignatures(); it.hasNext();)
        {
            PGPSignature certification = (PGPSignature)it.next();

            certification.init(new JcaPGPContentVerifierBuilderProvider().setProvider("SC"), pubKeyRing.getPublicKey());

            if (!certification.verifyCertification((String)pubKeyRing.getPublicKey().getUserIDs().next(), pubKeyRing.getPublicKey()))
            {
                fail("self certification does not verify");
            }
        }

        if (pubKeyRing.getPublicKey().getBitStrength() != 256)
        {
            fail("incorrect bit strength returned");
        }

        //
        // Read the private key
        //
        PGPSecretKeyRing        secretKeyRing = new PGPSecretKeyRing(testPrivKey, new JcaKeyFingerprintCalculator());

        PGPPrivateKey privKey = secretKeyRing.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(testPasswd));

        generateAndSign();
        generateAndSignBC();

        //
        // sExpr
        //
        PGPSecretKey key = PGPSecretKey.parseSecretKeyFromSExpr(new ByteArrayInputStream(sExprKey), new JcePBEProtectionRemoverFactory("test".toCharArray()), new JcaKeyFingerprintCalculator());

        PGPSignatureGenerator signGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PGPPublicKey.ECDSA, HashAlgorithmTags.SHA256).setProvider("SC"));

        signGen.init(PGPSignature.BINARY_DOCUMENT, key.extractPrivateKey(null));

        signGen.update("hello world!".getBytes());

        PGPSignature sig = signGen.generate();

        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("SC"), key.getPublicKey());

        sig.update("hello world!".getBytes());

        if (!sig.verify())
        {
            fail("signature failed to verify!");
        }
    }

    public String getName()
    {
        return "PGPECDSATest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPECDSATest());
    }
}
