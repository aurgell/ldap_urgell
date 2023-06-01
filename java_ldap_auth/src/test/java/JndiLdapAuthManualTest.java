
import java.util.ArrayList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.util.Hashtable;
import java.util.List;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import static org.assertj.core.api.Assertions.fail;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(FrameworkRunner.class)
@CreateLdapServer(transports = {
    @CreateTransport(protocol = "LDAP", address = "localhost", port = 8084)})
@CreateDS(
        allowAnonAccess = false, partitions = {
            @CreatePartition(name = "TestPartition", suffix = "dc=baeldung,dc=com")})
@ApplyLdifFiles({"users.ldif"})
// class marked as manual test, as it has to run independently from the other unit tests in the module
public class JndiLdapAuthManualTest extends AbstractLdapTestUnit {

    private static void authenticateUser(Hashtable<String, String> environment) throws Exception {

        DirContext context = new InitialDirContext(environment);
        context.close();
    }

    private static void listUser(Hashtable<String, String> environment) throws Exception {

        DirContext context = new InitialDirContext(environment);
        Attributes attributes = context.getAttributes("cn=Joe Simms,ou=Users,dc=baeldung,dc=com");

        for (NamingEnumeration ae = attributes.getAll(); ae.hasMore();) {
            Attribute attr = (Attribute) ae.next();
            System.out.println("attribute: " + attr.getID());
            /* Print each value */
            for (NamingEnumeration e = attr.getAll(); e.hasMore();
                    System.out.println("value: " + e.next()))
	;
        }
        context.close();
    }

    private static void modifyUser(Hashtable<String, String> environment) throws Exception {

        DirContext context = new InitialDirContext(environment);

        ModificationItem[] mods = new ModificationItem[2];

        Attribute mod0 = new BasicAttribute("number", "626626262");
        Attribute mod1 = new BasicAttribute("alias", "test");

        mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, mod0);
        mods[1] = new ModificationItem(DirContext.ADD_ATTRIBUTE, mod1);
        context.close();
    }

    @Test
    public void listUserAtt() throws Exception {

        final Hashtable<String, String> environment = new Hashtable<String, String>();
        environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(Context.PROVIDER_URL, "ldap://localhost:8084");
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");

        environment.put(Context.SECURITY_PRINCIPAL, "cn=Joe Simms,ou=Users,dc=baeldung,dc=com");
        environment.put(Context.SECURITY_CREDENTIALS, "12345");

        assertThatCode(new ThrowingCallable() {
            @Override
            public void call() throws Exception {
                listUser(environment);
            }
        }).doesNotThrowAnyException();
    }

    @Test
    public void changeUserPhone() throws Exception {
        final Hashtable<String, String> environment = new Hashtable<String, String>();
        environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(Context.PROVIDER_URL, "ldap://localhost:8084");
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");
        environment.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        environment.put(Context.SECURITY_CREDENTIALS, "secret");

        assertThatCode(new ThrowingCallable() {
            @Override
            public void call() throws Exception {
                modifyUser(environment);
            }
        }).doesNotThrowAnyException();

    }

    @Test
    public void authUser_CorrectPassword() throws Exception {

        final Hashtable<String, String> environment = new Hashtable<String, String>();
        environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(Context.PROVIDER_URL, "ldap://localhost:8084");
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");

        environment.put(Context.SECURITY_PRINCIPAL, "cn=Joe Simms,ou=Users,dc=baeldung,dc=com");
        environment.put(Context.SECURITY_CREDENTIALS, "12345");

        assertThatCode(new ThrowingCallable() {
            @Override
            public void call() throws Exception {
                authenticateUser(environment);
            }
        }).doesNotThrowAnyException();

    }

    @Test
    public void authUser_WrongPassword() throws Exception {

        Hashtable<String, String> environment = new Hashtable<String, String>();
        environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(Context.PROVIDER_URL, "ldap://localhost:8084");
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");

        environment.put(Context.SECURITY_PRINCIPAL, "cn=Joe Simms,ou=Users,dc=baeldung,dc=com");
        environment.put(Context.SECURITY_CREDENTIALS, "wronguserpw");

        try {
            authenticateUser(environment);
            // If the authentication was successful, fail the test
            fail("Expected AuthenticationException to be thrown, but no exception was thrown");
        } catch (AuthenticationException e) {
            // The AuthenticationException was thrown as expected
        }

    }

    @Test
    public void searchAuthUserAsAdmin_Correct() throws Exception {

        // first authenticate against LDAP as admin to search up DN of user : Joe Simms
        final Hashtable<String, String> environment = new Hashtable<String, String>();
        environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(Context.PROVIDER_URL, "ldap://localhost:8084");
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");
        environment.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        environment.put(Context.SECURITY_CREDENTIALS, "secret");

        DirContext adminContext = new InitialDirContext(environment);

        // define the search filter to find the person with CN : Joe Simms
        String filter = "(&(objectClass=person)(cn=Joe Simms))";

        // declare the attributes we want returned for the object being searched
        String[] attrIDs = {"cn"};

        // define the search controls
        SearchControls searchControls = new SearchControls();
        searchControls.setReturningAttributes(attrIDs);
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        // search for User with filter cn=Joe Simms
        NamingEnumeration<SearchResult> searchResults = adminContext.search("dc=baeldung,dc=com", filter, searchControls);
        if (searchResults.hasMore()) {

            SearchResult result = (SearchResult) searchResults.next();
            Attributes attrs = result.getAttributes();

            String distinguishedName = result.getNameInNamespace();
            assertThat(distinguishedName).isEqualTo("cn=Joe Simms,ou=Users,dc=baeldung,dc=com");

            String commonName = attrs.get("cn").toString();
            assertThat(commonName).isEqualTo("cn: Joe Simms");

            // authenticate new context with DN for user Joe Simms, using correct password
            environment.put(Context.SECURITY_PRINCIPAL, distinguishedName);
            environment.put(Context.SECURITY_CREDENTIALS, "12345");

            assertThatCode(new ThrowingCallable() {
                @Override
                public void call() throws Exception {
                    authenticateUser(environment);
                }
            }).doesNotThrowAnyException();
        }

        adminContext.close();
    }

    @Test
    public void searchAuthUserAsAdmin_Wrong() throws Exception {

        // first authenticate against LDAP as admin to search up DN of user : Joe Simms
        Hashtable<String, String> environment = new Hashtable<String, String>();
        environment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(Context.PROVIDER_URL, "ldap://localhost:8084");
        environment.put(Context.SECURITY_AUTHENTICATION, "simple");
        environment.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        environment.put(Context.SECURITY_CREDENTIALS, "secret");
        DirContext adminContext = new InitialDirContext(environment);

        // define the search filter to find the person with CN : Joe Simms
        String filter = "(&(objectClass=person)(cn=Joe Simms))";

        // declare the attributes we want returned for the object being searched
        String[] attrIDs = {"cn"};

        // define the search controls
        SearchControls searchControls = new SearchControls();
        searchControls.setReturningAttributes(attrIDs);
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        // search for User with filter cn=Joe Simms
        NamingEnumeration<SearchResult> searchResults = adminContext.search("dc=baeldung,dc=com", filter, searchControls);
        if (searchResults.hasMore()) {

            SearchResult result = (SearchResult) searchResults.next();
            Attributes attrs = result.getAttributes();

            String distinguishedName = result.getNameInNamespace();
            assertThat(distinguishedName).isEqualTo("cn=Joe Simms,ou=Users,dc=baeldung,dc=com");

            String commonName = attrs.get("cn").toString();
            assertThat(commonName).isEqualTo("cn: Joe Simms");

            // authenticate new context with DN for user Joe Simms, using wrong password
            environment.put(Context.SECURITY_PRINCIPAL, distinguishedName);
            environment.put(Context.SECURITY_CREDENTIALS, "wronguserpassword");

            try {
                authenticateUser(environment);
                // If the authentication was successful, fail the test
                fail("Expected AuthenticationException to be thrown, but no exception was thrown");
            } catch (AuthenticationException e) {
                // The AuthenticationException was thrown as expected
            }
        }

        adminContext.close();
    }
}
