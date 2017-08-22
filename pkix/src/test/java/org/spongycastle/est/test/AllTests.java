package org.spongycastle.est.test;

import java.security.Security;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.spongycastle.jce.provider.BouncyCastleProvider;

public class AllTests
    extends TestCase
{
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        if (Security.getProvider(BC) != null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
        throws Exception
    {
        TestSuite suite = new TestSuite("EST tests");

        suite.addTestSuite(ESTParsingTest.class);
        suite.addTestSuite(HostNameAuthorizerMatchTest.class);

        return new ESTTestSetup(suite);
    }
}
