import org.owasp.benchmark.helpers.LDAPServer;
public class LdapKeepAlive {
    public static void main(String[] args) throws Exception {
        new LDAPServer();
        System.out.println("[LdapKeepAlive] LDAPServer constructed, port 10389 should be listening");
        Thread.sleep(Long.MAX_VALUE);
    }
}
