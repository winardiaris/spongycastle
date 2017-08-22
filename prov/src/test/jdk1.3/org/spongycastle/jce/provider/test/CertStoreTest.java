package org.spongycastle.jce.provider.test;
 
import java.io.ByteArrayInputStream;
import java.security.Security;

import org.spongycastle.jce.PrincipalUtil;
import org.spongycastle.jce.cert.CertStore;
import java.security.cert.CertificateFactory;
import org.spongycastle.jce.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import org.spongycastle.jce.cert.X509CRLSelector;
import org.spongycastle.jce.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.test.SimpleTestResult;
import org.spongycastle.util.test.Test;
import org.spongycastle.util.test.TestResult;

public class CertStoreTest
    implements Test
{

    public TestResult perform()
    {
        try
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509",
                    "SC");

            X509Certificate rootCert = (X509Certificate)cf
                    .generateCertificate(new ByteArrayInputStream(
                            CertPathTest.rootCertBin));
            X509Certificate interCert = (X509Certificate)cf
                    .generateCertificate(new ByteArrayInputStream(
                            CertPathTest.interCertBin));
            X509Certificate finalCert = (X509Certificate)cf
                    .generateCertificate(new ByteArrayInputStream(
                            CertPathTest.finalCertBin));
            X509CRL rootCrl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(
                    CertPathTest.rootCrlBin));
            X509CRL interCrl = (X509CRL)cf
                    .generateCRL(new ByteArrayInputStream(
                            CertPathTest.interCrlBin));

            // Testing CollectionCertStore generation from List
            List list = new ArrayList();
            list.add(rootCert);
            list.add(interCert);
            list.add(finalCert);
            list.add(rootCrl);
            list.add(interCrl);
            CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(
                    list);
            CertStore store = CertStore.getInstance("Collection", ccsp, "SC");

            // Searching for rootCert by subjectDN
            X509CertSelector targetConstraints = new X509CertSelector();
            targetConstraints.setSubject(PrincipalUtil.getSubjectX509Principal(rootCert).getName());
            Collection certs = store.getCertificates(targetConstraints);
            if (certs.size() != 1 || !certs.contains(rootCert))
            {
                return new SimpleTestResult(false, this.getName()
                        + ": rootCert not found by subjectDN");
            }

            // Searching for rootCert by subjectDN encoded as byte
            targetConstraints = new X509CertSelector();
            targetConstraints.setSubject(PrincipalUtil.getSubjectX509Principal(rootCert)
                    .getEncoded());
            certs = store.getCertificates(targetConstraints);
            if (certs.size() != 1 || !certs.contains(rootCert))
            {
                return new SimpleTestResult(false, this.getName()
                        + ": rootCert not found by encoded subjectDN");
            }

            // Searching for rootCert by public key encoded as byte
            targetConstraints = new X509CertSelector();
            targetConstraints.setSubjectPublicKey(rootCert.getPublicKey()
                    .getEncoded());
            certs = store.getCertificates(targetConstraints);
            if (certs.size() != 1 || !certs.contains(rootCert))
            {
                return new SimpleTestResult(false, this.getName()
                        + ": rootCert not found by encoded public key");
            }

            // Searching for interCert by issuerDN
            targetConstraints = new X509CertSelector();
            targetConstraints.setIssuer(PrincipalUtil.getSubjectX509Principal(rootCert)
                    .getEncoded());
            certs = store.getCertificates(targetConstraints);
            if (certs.size() != 2)
            {
                return new SimpleTestResult(false, this.getName()
                        + ": did not found 2 certs");
            }
            if (!certs.contains(rootCert))
            {
                return new SimpleTestResult(false, this.getName()
                        + ": rootCert not found");
            }
            if (!certs.contains(interCert))
            {
                return new SimpleTestResult(false, this.getName()
                        + ": interCert not found");
            }

            // Searching for rootCrl by issuerDN
            X509CRLSelector targetConstraintsCRL = new X509CRLSelector();
            targetConstraintsCRL.addIssuerName(PrincipalUtil.getIssuerX509Principal(rootCrl)
                    .getEncoded());
            Collection crls = store.getCRLs(targetConstraintsCRL);
            if (crls.size() != 1 || !crls.contains(rootCrl))
            {
                return new SimpleTestResult(false, this.getName()
                        + ": rootCrl not found");
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, this.getName()
                    + ": exception - " + e.toString(), e);
        }

        return new SimpleTestResult(true, this.getName() + ": Okay");
    }

    public String getName()
    {
        return "CertStore";
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new CertStoreTest();
        TestResult        result = test.perform();

        System.out.println(result.toString());
    }

}

