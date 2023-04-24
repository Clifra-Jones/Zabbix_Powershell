enum InventoryModes {
    Disabled = -1
    Manual = 0
    Automatic = 1
}

enum IpmiAuthTypes {
    Default = -1
    None = 0
    MD2 = 1
    MD5 = 2
    Straight = 4
    OEM = 5
    RMCP = 6
}


enum IpmiPrivileges {
    Callback = 1
    User = 2
    Operator = 3
    Admin = 4
    OEM = 5
}

enum HostStatus {
    Monitored = 0
    UnMonitored = 1
}

enum TlsConnections {
    NoEncryption = 1
    PSK = 2
    Certificate = 4
}

enum CheckType {
    SNMPv1_agent = 10
    IMAP = 7
    SNMPv2_agent = 11
    ICMP_ping = 12
    SMTP = 2
    LDAP = 1
    FTP = 3
    NNTP = 6
    HTTP = 4
    POP = 5
    TCP = 8
    Telnet = 15
    Zabbix_agent = 9
    HTTPS = 14
    SSH = 0
    SNMPv3_agent = 13
}

enum PrivProtocol {
    AES128 = 1
    AES192 = 2
    AES256 = 3
    AES192C = 4
    AES256C = 5
}

enum SecurityLevel {
    noAuthNoPriv = 1
    authNoPriv = 2
    authPriv = 3
}

enum AuthProtocol {
    SHA1 = 1
    SHA224 = 2
    SHA256 = 3
    SHA384 = 4
    SHA512 = 5
}

enum HostSource {
    DNS = 1
    IP= 1
}

enum VisibleNameSource {
    DNS = 1
    IP = 2
}

enum ItemsType {
    ZabbixAgent = 0
    ZabbixTrapper = 2
    SimpleCheck = 3
    ZabbixInternal = 5
    ZabbixAgentActive = 7
    ZabbixAggregate = 8
    Webitem = 9
    ExternalCheck = 10
    DatabaseMonitor = 11
    IPMIAgent = 12
    SSHAgent = 13
    TelnetAgent = 14
    Calculated = 15
    JMXAgent = 16
    SNMPTrap = 17
    DependentItem= 18
    HTTPAgent = 10
    SNMPAgent =10
}

enum ItemValueType {
    NumericFloat = 0
    Character = 1
    Log = 2
    NumericUnsigned = 3
    Test = 4
}

enum ItemAuthType {
    None = 0
    Password = 0
    Basic = 1
    PublicKey = 1
    NTLM = 2
    Kerberos = 3
}

enum ItemPostType {
    Raw = 0
    JSON = 2
    XML = 3
}

enum RequestMethod {
    Get = 0
    Post = 1
    Put = 2
    Head = 3
}

enum RetrieveMode {
    Body = 0
    Headers = 1
    Both = 2
}