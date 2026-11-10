public class StartLdap {
    public static void main(String[] args) throws Exception {
        // LDAPServer ctor runs init() (starts ApacheDS on 10389) + seeds 3 test users
        new org.owasp.benchmark.helpers.LDAPServer();
        System.out.println("[StartLdap] LDAP server up on 10389");
        Thread.sleep(Long.MAX_VALUE);
    }
}
