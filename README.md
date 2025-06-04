# OPNsense-Setup

![Dashboard](Dashboard.png)

## Virtual bridge

Node name -> Network -> Create a second virtual bridge with IP address 192.168.1.2.

## Create OPNsense VM

Create OPNsense VM as usual, note that:
- OPNsense is FreeBSD, not Linux, so mark the OS as "other".
- OPNsense supports QEMU guest agent, so make sure that checkbox is ticked.
- OPNsense does not support Secure Boot, so uncheck pre-enrolled keys for system settings.
- Use vmbr0 for networking.
- Do not start the VM after creation.

![OS type](OS-Type.png)
![System settings](System-Settings.png)

## Network & Firewalling

- Node name -> Hardware -> Add a second network interface bridging to the new virtual bridge.

![net1](net1.png)

- Node name -> Firewall -> IPset
    - Create ipfilter-net0 -> Add all public IP addresses OPNsense is supposed to handle (Basically, all public IPs except those of iDRAC and Proxmox).
    - Create ipfilter-net1 -> 192.168.1.1.

- Node name -> Firewall -> Add approprieate firewall rules

![Proxmox firewall](Proxmox-Firewall.png)

**Note**: These firewall rules will stop VMs behind OPNsense from *initiating* any non TCP, UDP, and ICMP connections.

- Firewall -> Options -> Enable Firewall, Router Advertisement, and IP filter

## OPNSense installation

Install OPNsense as usual, note that:
- Use UHS as the filesystem, as the VM itself already runs inside of a ZVOL.
- The default password for both the root and installer user is "opnsense".

## Configure interfaces

- Open console and configure interfaces. Note that by default OPNsense sets net0 as "LAN" and net1 as "WAN", which is the opposite of what we want.
- Open shell and run `pfctl -d` to temporarily disable the packet filter.
- Add the following rules to make sure the web interface is reachable on WAN:

![WAN Rules](WAN-Rules.png)

## Configure OPNsense

- System -> Firmware
    - Updates -> Check for updates
    - Plugins -> Install the following:
        - os-acme-client
        - os-chrony
        - os-crowdsec
        - os-etpro-telemetry
        - os-intrusion-detection-content-ptopen
        - os-intrusion-detection-content-snort-vrt
        - os-qemu-guest-agent, os-sunnyvalley
        - os-theme-vincuna
    - Refresh plugins -> Install os-sensei
    - Reboot

- Services -> ACME Client
    - Settings -> Settings
        - Enable plugin
        - Uncheck Show introduction pages
    - Accounts -> Register an account. 
    - Update CAA records with your DNS provider. The account info is stored in `/var/etc/acme-client/accounts`/
    - Challenge Types -> Add challenge
    - Certificates -> Add certificates (EC-256) 

- System -> Settings -> Administration
    - Change SSL certificate to one issued by ACME
    - SSL Ciphers -> Restrict to this suite: ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256;
    - HTTP Strict Transport Security -> Enable
    - Primary Console -> Serial Console
    - Secondary Console -> VGA Console

- System -> Settings -> Cron
    - Add the following:
![Automatic firmware update](Automatic-Firmware-Update.png)    

- System -> Settings -> General
    - Domain -> Set approprieate domain name
    - Theme -> vincuna
    - DNS servers -> Set appropriate DNS servers
    - DNS search domain -> Set appropriate DNS search domain
    - DNS server options -> Uncheck "Allow DNS server list to be overridden by DHCP/PPP on WAN"

- System -> Access
    - Users
        - Open the root user and add the OTP seed to your phone
    - Servers
        - Follow [this guide](https://docs.opnsense.org/manual/how-tos/two_factor.html) to add the TOTP server and use it for Auth. Consider reversing the token order.

- System -> Trust -> Certificates
    - Delete the self-signed "Web GUI TLS certificate" which is no longer necessary

- System -> Trust -> Settings
    - Check "Store CRL's"
    - Check "Auto fetch CRL's"
    - Uncheck "Enable legacy"

- Interfaces -> LAN
    - Set IP address as 192.168.1.1/24
    - Check "Block bogon networks"

- Interfaces -> Virtual IPs
    - Add other WAN IPs (Except iDRAC, Proxmox, and OPNsense's own IP), deny service binding

- Firewall -> NAT -> Port Forward -> New Rule
    - Interface: LAN
    - TCP/IP Version: IPv4
    - Protocol: TCP/UDP
    - Check "Destination / Invert"
    - Destination: LAN address
    - Destination port range: from DNS to DNS
    - Redirect target IP: 127.0.0.1
    - Redirect target port: DNS

- Firewall -> NAT -> Port Forward -> Clone the previous rule
    - TCP/IP Version: IPv6
    - Redirect target IP: ::1

- Firewall -> Settings
    - Advanced
        - Check "Reflection for port forwards"
        - Check "Reflection for 1:1"
        - Check "Reflection for 1:1"
        - Bogon Networks -> Update Frequency -> Daily
        - Check "Disable administration anti-lockout rule"
        - Enable syncookies -> Always

- Services -> Chrony
    - Check "Enable"
    - Check "NTS Client Support"
    - Allowed Networks -> Remove 0.opnsense.pool.ntp.org, add 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and fc00::/7.

- Services -> Dnsmasq DNS & DHCP 
    - Not actually gonna use this, but check "DNSSEC" anyways.

- Services -> Intrusion Detection
    - Downloads
        - Add snort_vrt.oinkcode and et_telemetry.token. Hit "Save".
        - Enable all of the rules except:
            - ET telemetry/emerging-chat
            - ET telemetry/emerging-deleted
            - ET telemetry/emerging-games
            - ET telemetry/emerging-hunting
            - ET telemetry/emerging-icmp_info
            - ET telemetry/emerging-imap
            - ET telemetry/emerging-inappropriate
            - ET telemetry/emerging-info
            - ET telemetry/emerging-policy (Dubious policies blocking things like ipinfo.io)
            - ET telemetry/emerging-pop3
            - ET telemetry/emerging-smtp
            - ET telemetry/tor
            - All OPNsense-App-detect rules
            - Snort VRT/app-detect
            - Snort VRT/browser-ie (Too many problems parsing)
            - Snort VRT/browser-other (Too many problems parsing)
            - Snort VRT/browser-webkit (Too many problems parsing)
            - Snort VRT/chat
            - Snort VRT/experimental
            - Snort VRT/file-identify (Too many problems parsing)
            - Snort VRT/file-other (Too many problems parsing)
            - Snort VRT/icmp
            - Snort VRT/icmp-info
            - Snort VRT/imap
            - Snort VRT/indicator-obfuscation
            - Snort VRT/info
            - Snort VRT/malware-cnc (Too many problems parsing)
            - Snort VRT/malware-other (Too many problems parsing)
            - Snort VRT/misc
            - Snort VRT/multimedia
            - Snort VRT/os-windows (Too many problems parsing)
            - Snort VRT/other-ids
            - Snort VRT/policy
            - Snort VRT/policy-multimedia
            - Snort VRT/policy-other
            - Snort VRT/policy-social
            - Snort VRT/pop3
            - Snort VRT/protocol-dns
            - Snort VRT/protocol-icmp
            - Snort VRT/protocol-imap
            - Snort VRT/protocol-other
            - Snort VRT/protocol-voip
            - Snort VRT/pua-other (Too many problems parsing)
            - Snort VRT/server-other (Too many problems parsing)
            - Snort VRT/server-webapp (Too many problems parsing)
            - Snort VRT/voip
        - Download and update rules
    - Settings
        - Check "Enabled"
        - IPS Mode -> Click on the link to go to advanced network and disable hardware offloading first, then check "IPS Mode"
        - Interfaces -> Make sure only WAN is selected
        - Pattern Matcher -> Hyperscan
    - Policy -> Create new policy
        - Priority 0
        - Rulesets -> All
        - Actions -> Alert
        - New action -> Drop
        - Description -> Drop All
    - Administration
        - Check "Enabled"
        - Check "IPS Mode"
        - Home Networks (if you don't see it, make sure advanced options are enabled) -> Clear all IPs, add WAN IP and virtual IPs

- Services -> Network Time
    - General -> Remove all NTP servers (We already have Chrony, we don't need ntpd to be running)

- Services -> Unbound DNS
    - General
        - Check "Enable DNSSEC Support"
    - Advanced
        - Check "Hide Identity"
        - Check "Hide Version"
        - Check "Prefetch DNS Key Support"
        - Check "Harden DNSSEC Data"
        - Check "Strict QNAME Minimisation"
        - Check "Prefetch Support"
    - Blocklist
        - Check "Enable"
        - Type of DNSBL
            - Abuse.ch Threatfox IOC Database
            - AdAway List
            - AdGuard List
            - Blocklist.site Abuse
            - Blocklist.site Ads
            - Blocklist.site Fraud
            - Blocklist.site Gambling
            - Blocklist.site Malware
            - Blocklist.site Phishing
            - Blocklist.site Ransomware
            - Blocklist.site Scam
            - Blocklist.site Tracking
            - EasyList
            - Easy Privacy
            - hagezi Fake-scams/fakes
            - hagezi Pop-Up Ads
            - hagezi Threat Inelligence Feeds
            - hagezi Gambling
            - OISD Domain Blocklist Ads
    - DNS over TLS
        - Add Cloudflare Gateway. Use `dig A your-endpoint.cloudflare-gateway.com` and `dig AAAA your-endpoint.cloudflare-gateway.com` to get the IP addresses to pin. Check `Forward first`.

- Reporting
    - Settings
        - Unbound DNS reporting -> Check "Enables local gathering of statistics."
    - Unbound DNS
        - Wait a few minutes. Whitelist `api.ipify.org` if blocked. 

- ZenArmor
    - Go through the installation wizard
        - Use Elasticsearch 8
        - Monitor the LAN interface, set security zone as "lan"
    - Policies -> Default
        - Security -> Enable all essential security except "Hacking" and "Firstly Seen Sites"
        - App Control -> Block "Ad Tracker" and "Ads"
        - Exclusions -> Disable Feedbacks
    - Settings
        - Reporting & Data
            - Community ID -> Disable
        - Cloud Threat Intelligence
            - Local Domains Name To Exclude From Cloud Queries -> Remove default 
        - Privacy
            - Help us improve ZenArmor -> Disable
            - Report Infrastructure Errors -> Disable

## Use as Proxmox's DNS server

Go to Proxmox -> Node Name -> System -> DNS
- Set the primary DNS server as 192.168.1.1
- Set 1.1.1.2 and 2606:4700:4700::1112