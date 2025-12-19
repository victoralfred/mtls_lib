package com.mtls;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;
import org.junit.platform.suite.api.SuiteDisplayName;

/**
 * Test suite that runs all unit tests.
 */
@Suite
@SuiteDisplayName("mTLS Java Bindings Test Suite")
@SelectClasses({
        ConfigTest.class,
        MtlsExceptionTest.class,
        PeerIdentityTest.class,
        ConnectionTest.class
})
public class AllTests {
    // This class remains empty, used only as a holder for the above annotations
}
