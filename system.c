/*
 * Bergamota-ng Command line interface (c) 2018 Cassiano Martin <cassiano@polaco.pro.br>
 * Copyright (c) 2018 Cassiano Martin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>

#include "utils.h"
#include "realtek.h"
#include "base64.h"

void firewall6_start(bool startup)
{
    int i = 0;
    char *rules[] = { "-t filter -F",
                      "-t mangle -F",
                      "-t filter -A INPUT ACCEPT",
                      "-t filter -A FORWARD ACCEPT",
                      "-t filter -A OUTPUT ACCEPT",
                      NULL
                    };

        if(config_item_active("network.ipv6.active"))
        {
            if(startup)
            {
                // sysctl setup
                sysctlwrite("net.ipv6.conf.all.forwarding", 1);
                sysctlwrite("net.ipv6.conf.all.use_tempaddr", 2);
                sysctlwrite("net.ipv6.conf.default.use_tempaddr", 2);

                sysctlwrite("net.ipv6.route.max_size", 8192);
                sysctlwrite("net.ipv6.route.gc_thresh", 180);
                sysctlwrite("net.ipv6.route.gc_elasticity", 20);
                sysctlwrite("net.ipv6.route.gc_timeout", 60);

                // insert iptables rules
                while(rules[i])
                    sysexec(true, "ip6tables", rules[i++]);
            }

        sysexec(true, "ip6tables", "-t filter -F custom-forward");
        sysexec(true, "ip6tables", "-t filter -F custom-input");
        sysexec(true, "ip6tables", "-F icmp-service");

        if(config_item_active("firewall.basic.wanping"))
            sysexec(true, "ip6tables", "-t filter -A icmp-service -i %s -p icmp -j ACCEPT", wan_devname());

        sysexec(true, "ip6tables", "-t filter -A icmp-service -i br0 -p icmp -j ACCEPT");
    }
}

void firewall_start(bool startup)
{
    int i = 0;
    char *rules[] = { "-t filter -F",
                      "-t mangle -F",
                      "-t nat -F",

                      // custom nat chains
                      "-t nat -N custom-forward",
                      "-t nat -N custom-postrouting",
                      "-t nat -N custom-prerouting",
                      "-t nat -N dhcp-broadcast",
                      "-t nat -N dns-redirect",
                      "-t nat -N hotspot-intercept",
                      "-t nat -N output-masq",
                      "-t nat -N port-forward-postrouting",
                      "-t nat -N port-forward-prerouting",
                      "-t nat -N route-postrouting",
                      "-t nat -N MINIUPNPD",
                      "-t nat -N MINIUPNPD-PREROUTING",
                      "-t nat -A PREROUTING -j MINIUPNPD-PREROUTING",
                      "-t nat -A PREROUTING -j dns-redirect",
                      "-t nat -A PREROUTING -j port-forward-prerouting",
                      "-t nat -A PREROUTING -j hotspot-intercept",
                      "-t nat -A PREROUTING -j custom-prerouting",
                      "-t nat -A OUTPUT -j dhcp-broadcast",
                      "-t nat -A POSTROUTING -j port-forward-postrouting",
                      "-t nat -A POSTROUTING -j custom-postrouting",
                      "-t nat -A POSTROUTING -j route-postrouting",
                      "-t nat -A POSTROUTING -j output-masq",
                      "-t nat -A dns-redirect -p udp --dport 53 -j REDIRECT --to-ports 53",

                      // custom mangle chains
                      "-t mangle -N accounting",
                      "-t mangle -N route-connmark",
                      "-t mangle -N route-dns",
                      "-t mangle -N route-postrouting",
                      "-t mangle -N route-prerouting",
                      "-t mangle -N rr-balance",
                      "-t mangle -N vpn-routing",
                      "-t mangle -A PREROUTING -j accounting",
                      "-t mangle -A PREROUTING -m conntrack --ctstate RELATED,ESTABLISHED -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff",
                      "-t mangle -A PREROUTING -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                      "-t mangle -A PREROUTING -j vpn-routing",
                      "-t mangle -A PREROUTING -j route-prerouting",
                      "-t mangle -A PREROUTING -j rr-balance",
                      "-t mangle -A PREROUTING -j route-connmark",
                      "-t mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
                      "-t mangle -A POSTROUTING -j accounting",
                      "-t mangle -A POSTROUTING -m conntrack --ctstate RELATED,ESTABLISHED -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff",
                      "-t mangle -A POSTROUTING -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                      "-t mangle -A POSTROUTING -j route-postrouting",
                      "-t mangle -A POSTROUTING -j route-dns",
                      "-t mangle -A POSTROUTING -j route-connmark",

                      // custom filter chains
                      "-t filter -N connlimit",
                      "-t filter -N custom-forward",
                      "-t filter -N custom-input",
                      "-t filter -N custom-output",
                      "-t filter -N dnsmasq-service",
                      "-t filter -N hotspot",
                      "-t filter -N hotspot-forward",
                      "-t filter -N mac-control",
                      "-t filter -N port-forward",
                      "-t filter -N services-inbound",
                      "-t filter -N icmp-service",
                      "-t filter -N vpn-inbound",
                      "-t filter -N vpn-routing",
                      "-t filter -N webadmin-service",
                      "-t filter -N MINIUPNPD",
                      "-t filter -N MINIUPNPD-FORWARD",
                      "-t filter -A INPUT -m conntrack --ctstate INVALID -j DROP",
                      "-t filter -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                      "-t filter -A INPUT -j mac-control",
                      "-t filter -A INPUT -m conntrack --ctstate NEW -j services-inbound",
                      "-t filter -A INPUT -m conntrack --ctstate NEW -j hotspot",
                      "-t filter -A INPUT -m conntrack --ctstate NEW -j vpn-inbound",
                      "-t filter -A INPUT -m conntrack --ctstate NEW -j vpn-routing",
                      "-t filter -A INPUT -m conntrack --ctstate NEW -j custom-input",
                      "-t filter -A INPUT -i lo -j ACCEPT",
                      "-t filter -A INPUT -j DROP",
                      "-t filter -A FORWARD -m conntrack --ctstate INVALID -j DROP",
                      "-t filter -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                      //"-t filter -A FORWARD -m connlimit --connlimit-above 9990 --connlimit-mask 8 -j DROP",
                      "-t filter -A FORWARD -j mac-control",
                      "-t filter -A FORWARD -m conntrack --ctstate NEW -j MINIUPNPD-FORWARD",
                      "-t filter -A FORWARD -m conntrack --ctstate NEW -j connlimit",
                      "-t filter -A FORWARD -m conntrack --ctstate NEW -j port-forward",
                      "-t filter -A FORWARD -m conntrack --ctstate NEW -j hotspot-forward",
                      "-t filter -A FORWARD -m conntrack --ctstate NEW -j custom-forward",
                      "-t filter -A OUTPUT -m conntrack --ctstate INVALID -j DROP",
                      "-t filter -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                      "-t filter -A OUTPUT -j custom-output",
                      "-t filter -A services-inbound -j webadmin-service",
                      "-t filter -A services-inbound -j dnsmasq-service",
                      "-t filter -A services-inbound -j icmp-service",
                      NULL
                    };

    if(startup)
    {
        // sysctl setup
        sysctlwrite("net.ipv4.ip_forward", 1);
        sysctlwrite("net.ipv4.ip_dynaddr", 1);
        sysctlwrite("net.ipv4.tcp_syncookies", 1);
        sysctlwrite("net.ipv4.icmp_ignore_bogus_error_responses", 1);
        sysctlwrite("net.ipv4.icmp_echo_ignore_broadcasts", 1);

        sysctlwrite("net.ipv4.route.max_size", 8192);
        sysctlwrite("net.ipv4.route.gc_thresh", 180);
        sysctlwrite("net.ipv4.route.gc_elasticity", 20);
        sysctlwrite("net.ipv4.route.gc_timeout", 60);

        sysctlwrite("net.ipv4.netfilter.ip_conntrack_tcp_timeout_established", 300);
        sysctlwrite("net.ipv4.netfilter.ip_conntrack_tcp_timeout_time_wait", 20);
        sysctlwrite("net.ipv4.netfilter.ip_conntrack_tcp_timeout_close", 20);
        sysctlwrite("net.ipv4.netfilter.ip_conntrack_udp_timeout", 90);
        sysctlwrite("net.ipv4.netfilter.ip_conntrack_udp_timeout_stream", 120);
        sysctlwrite("net.ipv4.netfilter.ip_conntrack_generic_timeout", 90);

        sysctlwrite("net.netfilter.nf_conntrack_max", 10000);
        sysctlwrite("net.netfilter.nf_conntrack_expect_max", 32);

        // insert iptables rules
        while(rules[i])
            sysexec(true, "iptables", rules[i++]);
    }

    sysexec(true, "iptables", "-t filter -F custom-forward");
    sysexec(true, "iptables", "-t filter -F custom-input");
    sysexec(true, "iptables", "-F icmp-service");

    if(config_item_active("firewall.basic.wanping"))
        sysexec(true, "iptables", "-t filter -A icmp-service -i %s -p icmp -j ACCEPT", wan_devname());

    sysexec(true, "iptables", "-t filter -A icmp-service -i br0 -p icmp -j ACCEPT");

    // advanced firewall    
    cJSON *next = config_get_node("firewall.advanced.rules");

    // only single depth array is allowed
    if(next->type == cJSON_Array)
    {
        for(int y=0; y<cJSON_GetArraySize(next); y++)
        {
            cJSON *array = cJSON_GetArrayItem(next, y);

            char *srcaddr = cJSON_GetObjectItem(array, "srcaddr")->valuestring;
            char *dstaddr = cJSON_GetObjectItem(array, "dstaddr")->valuestring;
            char *proto = cJSON_GetObjectItem(array, "protocol")->valuestring;
            char *port = cJSON_GetObjectItem(array, "port")->valuestring;
            char *act = cJSON_GetObjectItem(array, "action")->valuestring;

            if(IS(act, "deny"))
                act = "DROP";
            else
                act = "CONTINUE";

            // if not specified, default to all ports range
            if(is_empty(port))
                port = "0:65535";

            if(IS(proto, "tcpudp"))
            {
                // tcp
                sysexec(true, "iptables", "-t filter -A custom-forward -s %s -d %s -p tcp -m multiport --ports %s -j %s", srcaddr, dstaddr, port, act);
                sysexec(true, "iptables", "-t filter -A custom-input -s %s -d %s -p tcp -m multiport --ports %s -j %s", srcaddr, dstaddr, port, act);
                // udp
                sysexec(true, "iptables", "-t filter -A custom-forward -s %s -d %s -p udp -m multiport --ports %s -j %s", srcaddr, dstaddr, port, act);
                sysexec(true, "iptables", "-t filter -A custom-input -s %s -d %s -p udp -m multiport --ports %s -j %s", srcaddr, dstaddr, port, act);
            }
            else
            if(IS(proto, "icmp"))
            {
                sysexec(true, "iptables", "-t filter -A custom-forward -s %s -d %s -p icmp -j %s", srcaddr, dstaddr, act);
                sysexec(true, "iptables", "-t filter -A custom-input -s %s -d %s -p icmp -j %s", srcaddr, dstaddr, act);
            }
            else
            {
                sysexec(true, "iptables", "-t filter -A custom-forward -s %s -d %s -p %s -m multiport --ports %s -j %s", srcaddr, dstaddr, proto, port, act);
                sysexec(true, "iptables", "-t filter -A custom-input -s %s -d %s -p %s -m multiport --ports %s -j %s", srcaddr, dstaddr, proto, port, act);
            }
        }
    }
}

void portforward_start()
{
    cJSON *next = config_get_node("portforward.redirects");
    const char *wandev = wan_devname();

    sysexec(true, "iptables", "-t filter -F port-forward");
    sysexec(true, "iptables", "-t nat -F port-forward-prerouting");

    // redirect custom ports at first
    if(next->type == cJSON_Array)
    {
        for(int y=0; y<cJSON_GetArraySize(next); y++)
        {
            cJSON *array = cJSON_GetArrayItem(next, y);

            char *addr = cJSON_GetObjectItem(array, "dstaddr")->valuestring;
            char *srcp = cJSON_GetObjectItem(array, "srcport")->valuestring;
            char *dstp = cJSON_GetObjectItem(array, "dstport")->valuestring;
            char *proto = cJSON_GetObjectItem(array, "protocol")->valuestring;

            if(IS(proto, "tcpudp"))
            {
                sysexec(true, "iptables", "-t filter -A port-forward -i %s -d %s/32 -p tcp --dport %s -j ACCEPT", wandev, addr, dstp);
                sysexec(true, "iptables", "-t nat -A port-forward-prerouting -i %s -p tcp --dport %s -j DNAT --to-destination %s:%s", wandev, srcp, addr, dstp);
                sysexec(true, "iptables", "-t filter -A port-forward -i %s -d %s/32 -p udp --dport %s -j ACCEPT", wandev, addr, dstp);
                sysexec(true, "iptables", "-t nat -A port-forward-prerouting -i %s -p udp --dport %s -j DNAT --to-destination %s:%s", wandev, srcp, addr, dstp);
            }
            else
            {
                sysexec(true, "iptables", "-t filter -A port-forward -i %s -d %s/32 -p %s --dport %s -j ACCEPT", wandev, addr, proto, dstp);
                sysexec(true, "iptables", "-t nat -A port-forward-prerouting -i %s -p %s --dport %s -j DNAT --to-destination %s:%s", wandev, proto, srcp, addr, dstp);
            }

            //TODO: hairpin nat
        }
    }

    if(config_item_active("firewall.dmz.active"))
    {
        char *addr = config_read_string("firewall.dmz.ipaddr");

        // redirect all to destination host
        sysexec(true, "iptables", "-t filter -A port-forward -i %s -d %s/32 -j ACCEPT", wandev, addr);
        sysexec(true, "iptables", "-t nat -A port-forward-prerouting -i %s -j DNAT --to-destination %s", wandev, addr);
    }
}

void miniupnpd_start()
{
    sysexec(true, "iptables", "-t filter -D services-inbound -i br+ -j ACCEPT");
    sysexec(true, "iptables", "-t filter -F MINIUPNPD-FORWARD");
    sysexec(true, "iptables", "-t nat -F MINIUPNPD-PREROUTING");
    sysexec(true, "iptables", "-t filter -F MINIUPNPD");
    sysexec(true, "iptables", "-t nat -F MINIUPNPD");

    syskill("minissdpd");
    syskill("miniupnpd");

    if(config_item_active("firewall.basic.wanupnp"))
    {
        const char *wan = wan_devname();
        char *lanaddr = config_read_string("network.lan.ipaddr");
        char *secondaryaddr = config_read_string("network.secondary_wireless.ipaddr");
        char *thirdaddr = config_read_string("network.third_wireless.ipaddr");

        sysexec(true, "iptables", "-t filter -I services-inbound -i br+ -j ACCEPT");
        sysexec(true, "iptables", "-t filter -I MINIUPNPD-FORWARD -i %s -j MINIUPNPD", wan);
        sysexec(true, "iptables", "-t nat -I MINIUPNPD-PREROUTING -i %s -j MINIUPNPD", wan);

        sysexec(true, "minissdpd", "-i br0 -i br1 -i br2");
        sysexec(true, "miniupnpd", "-i %s -a %s -a %s -a %s -u b4cc1925-eaf0-40f5-b50c-98f1e02d8c42 -m BERGAMOTA -z BERGAMOTA", wan, lanaddr, secondaryaddr, thirdaddr);
    }
}

void dnsmasq_start(bool startup)
{
//    in_addr_t addr;
//    in_addr_t mask;
//    struct in_addr start;
//    struct in_addr end;

    const char *conf = "user=nobody\n"
                       "group=nobody\n"
                       "domain=%s\n"
                       "domain-needed\n"
                       "bogus-priv\n"
                       "expand-hosts\n"
                       "localise-queries\n"
                       "dhcp-authoritative\n"
                       "stop-dns-rebind\n"
                       "strict-order\n"
                       "rebind-localhost-ok\n"
                       "conf-dir=/etc/dnsmasq.d\n"
                       "resolv-file=/etc/resolv.dnsmasq\n"
                       "except-interface=eth1";

    const char *hostsfile = "127.0.0.1 localhost\n"
                            "127.0.0.1 bergamota-ng\n"
                            "%s bergamota-ng";

    // disable DNSmasq when bridge mode is active
    if(IS(config_read_string("network.wan.mode"), "bridge"))
    {
        char *dns1 = config_read_string("network.dns.dns1");

        if(!is_empty(dns1))
            save_configfile("/etc/resolv.conf", "nameserver %s", dns1);

        return;
    }

    save_configfile("/etc/dnsmasq.conf", conf, config_read_string("system.hostname"));

    if(file_exists("/etc/dnsmasq.d/dhcp"))
        unlink("/etc/dnsmasq.d/dhcp");

    if(config_item_active("network.dhcp.active"))
    {
        save_configfile("/etc/dnsmasq.d/dhcp", "dhcp-range=%s,%s,%sh\n", config_read_string("network.dhcp.start"),
                                                                         config_read_string("network.dhcp.end"),
                                                                         config_read_string("network.dhcp.leasetime"));

        concat_configfile("/etc/dnsmasq.d/dhcp", "dhcp-range=%s,%s,%sh\n", config_read_string("network.dhcp.secondary_start"),
                                                                           config_read_string("network.dhcp.secondary_end"),
                                                                           config_read_string("network.dhcp.leasetime"));

        concat_configfile("/etc/dnsmasq.d/dhcp", "dhcp-range=%s,%s,%sh\n", config_read_string("network.dhcp.third_start"),
                                                                           config_read_string("network.dhcp.third_end"),
                                                                           config_read_string("network.dhcp.leasetime"));
    }

    save_configfile("/etc/dnsmasq.d/fwdns", "host-record=bergamota-ng,%s\n", config_read_string("network.lan.ipaddr"));

    save_configfile("/etc/hosts", hostsfile, config_read_string("network.lan.ipaddr"));

    if(file_exists("/etc/dnsmasq.d/fixedleases"))
        unlink("/etc/dnsmasq.d/fixedleases");

    sysexec(true, "iptables", "-F mac-control");
    sysexec(true, "iptables", "-F dnsmasq-service");
    sysexec(true, "iptables", "-A dnsmasq-service -i br0 -p udp -m udp --dport 53 -j ACCEPT");
    sysexec(true, "iptables", "-A dnsmasq-service -i br0 -p udp -m udp --dport 67 -j ACCEPT");

    if(config_item_active("network.secondary_wireless.active"))
    {
        sysexec(true, "iptables", "-A dnsmasq-service -i %s -p udp -m udp --dport 53 -j ACCEPT", "br1");
        sysexec(true, "iptables", "-A dnsmasq-service -i %s -p udp -m udp --dport 67 -j ACCEPT", "br1");
    }
    
    if(config_item_active("network.third_wireless.active"))
    {
        sysexec(true, "iptables", "-A dnsmasq-service -i %s -p udp -m udp --dport 53 -j ACCEPT", "br2");
        sysexec(true, "iptables", "-A dnsmasq-service -i %s -p udp -m udp --dport 67 -j ACCEPT", "br2");
    }

    // generate fixed leases file
    cJSON *next = config_get_node("network.dhcp.leases");

    // only single depth array is allowed
    if(next->type == cJSON_Array)
    {
        for(int y=0; y<cJSON_GetArraySize(next); y++)
        {
            cJSON *array = cJSON_GetArrayItem(next, y);

            char *ipaddr = cJSON_GetObjectItem(array, "ipaddr")->valuestring;
            char *mac = cJSON_GetObjectItem(array, "macaddr")->valuestring;
            char *blocked = cJSON_GetObjectItem(array, "blocked")->valuestring;
            char *restricted = cJSON_GetObjectItem(array, "restrict")->valuestring;
            char *iface = cJSON_GetObjectItem(array, "iface")->valuestring;

            DEBUG("New lease: %s[%s], blocked: %s", ipaddr, mac, blocked);

            // check if this address is blocked from network
            if(IS(blocked, "true"))
            {
                sysexec(true, "iptables", "-A mac-control -s %s -j DROP", ipaddr);
                sysexec(true, "iptables", "-A mac-control -d %s -j DROP", ipaddr);
                sysexec(true, "iptables", "-A mac-control -m mac --mac-source %s -j DROP", mac);  // TODO: test if its working
                sysexec(true, "iptables", "-A mac-control -m mac --mac-destination %s -j DROP", mac);  // TODO: test if its working
            }

            if(IS(restricted, "true"))
            {
                if(!IS(iface, "br0"))
                {
                    sysexec(true, "iptables", "-A mac-control -i br0 -m mac --mac-source %s -j REJECT", mac);  // TODO: test if its working
                    sysexec(true, "iptables", "-A mac-control -i br0 -m mac --mac-destination %s -j REJECT", mac);  // TODO: test if its working
                }

                if(!IS(iface, "br1"))
                {
                    sysexec(true, "iptables", "-A mac-control -i br1 -m mac --mac-source %s -j REJECT", mac);  // TODO: test if its working
                    sysexec(true, "iptables", "-A mac-control -i br1 -m mac --mac-destination %s -j REJECT", mac);  // TODO: test if its working
                }

                if(!IS(iface, "br2"))
                {
                    sysexec(true, "iptables", "-A mac-control -i br2 -m mac --mac-source %s -j REJECT", mac);  // TODO: test if its working
                    sysexec(true, "iptables", "-A mac-control -i br2 -m mac --mac-destination %s -j REJECT", mac);  // TODO: test if its working
                }
            }

            concat_configfile("/etc/dnsmasq.d/fixedleases", "dhcp-host=%s,%s,1h\n", mac, ipaddr);
        }
    }

    // ipv6 address
    if(config_item_active("network.ipv6.active"))
    {
        char *mode = config_read_string("network.ipv6.lan_mode");

        if(IS(mode, "radv"))
        {
            write_textfile("/etc/dnsmasq.d/ipv6-ra", "enable-ra", false);
            write_textfile("/etc/dnsmasq.d/ipv6-dhcp", "dhcp-range=tag:br*,::1,constructor:br*, ra-stateless, ra-names, 12h", false);
        }
        else
        if(IS(mode, "dhcp"))
        {
            write_textfile("/etc/dnsmasq.d/ipv6-dhcp", "dhcp-range=::1, ::ffff:ffff, constructor:br*, ra-names, 64, 12h", false);
        }
    }

//    // secondary wifi network address
//    addr = a_to_hl(config_read_string("network.secondary_wireless.ipaddr"));
//    mask = a_to_hl(config_read_string("network.secondary_wireless.netmask"));
//
//    // calc last IP address
//    start.s_addr = htonl(addr+1);
//    end.s_addr = htonl((addr|~mask)-1);
//    concat_configfile("/etc/dnsmasq.d/dhcp", "dhcp-range=%s,", inet_ntoa(start));
//    concat_configfile("/etc/dnsmasq.d/dhcp", "%s,1h\n", inet_ntoa(end));
//
//    // third wifi network address
//    addr = a_to_hl(config_read_string("network.third_wireless.ipaddr"));
//    mask = a_to_hl(config_read_string("network.third_wireless.netmask"));
//
//    // calc last IP address
//    start.s_addr = htonl(addr+1);
//    end.s_addr = htonl((addr|~mask)-1);
//    concat_configfile("/etc/dnsmasq.d/dhcp", "dhcp-range=%s,", inet_ntoa(start));
//    concat_configfile("/etc/dnsmasq.d/dhcp", "%s,1h\n", inet_ntoa(end));

    if(!startup)
        syskill("dnsmasq");

    sysexec(false, "dnsmasq", "-C /etc/dnsmasq.conf");
}

void wan_start(bool startup)
{
    char *wifiopmode = config_read_string("network.wireless.opmode");
    char *mode = config_read_string("network.wan.mode");
    char *mac = config_read_string("network.wan.macaddr");
    char *mtu = config_read_string("network.wan.mtu");

    char *v4pwd = config_read_string("network.wan.pppoe_password");
    char *v4usr = config_read_string("network.wan.pppoe_username");
    char *v6pwd = config_read_string("network.ipv6.pppoe_password");
    char *v6usr = config_read_string("network.ipv6.pppoe_username");

    if(!startup)
    {
        sysexec(true, "ip", "link set eth1 down");
        sysexec(true, "ip", "-4 addr flush dev eth1");
        sysexec(true, "ip", "-4 route flush table main dev eth1");
        sysexec(true, "iptables", "-F output-masq -t nat");
        syskill("dhclient");
        syskill("udhcpc");
        syskill("pppd");
    }

    if(IS(mode, "bridge"))
    {
        DEBUG("WAN is in bridge mode");

        if(startup)
        {
            procwrite("/proc/rtk_vlan_support", "1");

            // global vlan
            if(config_item_active("network.wan.enable_vlan"))
            {
                char *vlanid = config_read_string("network.wan.vlan_id");

                //global_vlan, is_lan, vlan, tag, id, pri, cfi, forwarding_rule
                procwrite("/proc/eth1/mib_vlan", "1 0 1 1 %s 0 0 0", vlanid);  // change port to LAN
            }
            else
                procwrite("/proc/eth1/mib_vlan", "0 1 0 0 0 0 0 0");  // internal chip vlan
                

            sysexec(true, "brctl", "addif br0 %s", "eth1");
            sysexec(true, "ip", "link set %s up", "eth1");
        }

        return;
    }
    else
    if(IS(wifiopmode, "repeater"))
    {
        DEBUG("WLAN is in repeater mode");

        if(startup)
        {
            procwrite("/proc/rtk_vlan_support", "1");
            procwrite("/proc/eth1/mib_vlan", "0 1 0 0 0 0 0");  // change port to LAN

            sysexec(true, "brctl", "addif br0 %s", "eth1");
            sysexec(true, "ip", "link set %s up", "eth1");
        }

        return;
    }
    else
    if(IS(mode, "pppoe"))
    {
        char *buf;
        const char *conf = "plugin rp-pppoe.so %s\n"
                           "user %s\n"
                           "password %s\n"
                           "usepeerdns\n"
                           "nolog\n"
                           "noipx\n"
                           "novj\n"
                           "nobsdcomp\n"
                           "noresolv\n"
                           "ktune\n"
                           "noipdefault\n"
                           "hide-password\n"
                           "lcp-echo-interval 20\n"
                           "lcp-echo-failure 3\n"
                           "noauth\n"
                           "persist\n"
                           "maxfail 0\n"
                           "ifname pppv4\n"
                           "mtu %s\n";

        asprintf(&buf, conf, "eth1", v4usr, v4pwd, config_read_string("network.wan.mtu"));

        write_textfile("/etc/pppd.conf", buf, false);

        // dual stack IPv6
        if(IS(v4pwd,v6pwd) && IS(v4usr, v6usr))
            write_textfile("/etc/pppd.conf", "+ipv6 ipv6cp-use-ipaddr\n", true);
        else
            write_textfile("/etc/pppd.conf", "noipv6\n", true);

        if(!is_empty(mac))
            sysexec(true, "ip", "link set eth1 address %s", mac);

        sysexec(true, "ip", "link set eth1 up");
        sysexec(false, "pppd", "file /etc/pppd.conf");

        free(buf);
    }
    else if(IS(mode, "dhcp"))
    {
        if(!is_empty(mtu))
            sysexec(true, "ip", "link set eth1 mtu %s", mtu);
        
        if(!is_empty(mac))
            sysexec(true, "ip", "link set eth1 address %s", mac);

        // obtain an IP lease trought DHCP
        sysexec(true, "ip", "link set eth1 up");
        sysexec(false, "udhcpc", "-S -b -s /usr/bin/udhcpc-script -i eth1");
    }
    else if(IS(mode, "static"))
    {
        if(!is_empty(mtu))
            sysexec(true, "ip", "link set eth1 mtu %s", mtu);
        if(!is_empty(mac))
            sysexec(true, "ip", "link set eth1 address %s", mac);

        sysexec(true, "ip", "-4 addr flush dev eth1");
        sysexec(true, "ip", "-4 addr add %s/%s dev eth1", config_read_string("network.wan.ipaddr"),
                                                     config_read_string("network.wan.netmask"));

        sysexec(true, "ip", "link set eth1 up");
        sysexec(true, "route", "del default");
        sysexec(true, "route", "add default gw %s dev eth1", config_read_string("network.wan.gateway"));
        //sysexec(true, "ip", "route replace default table main via %s dev %s", config_read_string("network.wan.gateway"), "eth1");

        if(!config_item_active("network.wan.disable_nat"))
            sysexec(true, "iptables", "-A output-masq -t nat -o eth1 -j SNAT --to-source %s", config_read_string("network.wan.ipaddr"));

        // write dns servers
        if(config_item_active("network.dns.active"))
        {
            char *dns1 = config_read_string("network.dns.dns1");
            char *dns2 = config_read_string("network.dns.dns2");
            char *dns3 = config_read_string("network.dns.dns3");
            char server[256];

            if(!is_empty(dns1))
            {
                snprintf(server, sizeof(server), "nameserver %s\n", dns1);
                write_textfile("/etc/resolv.dnsmasq", server, false);
            }
            if(!is_empty(dns2))
            {
                snprintf(server, sizeof(server), "nameserver %s\n", dns2);
                write_textfile("/etc/resolv.dnsmasq", server, true);
            }
            if(!is_empty(dns3))
            {
                snprintf(server, sizeof(server), "nameserver %s\n", dns3);
                write_textfile("/etc/resolv.dnsmasq", server, true);
            }
        }
    }
    else if(IS(mode, "disabled"))
    {
        DEBUG("wan disabled");
        return;
    }

    // global vlan
    if(config_item_active("network.wan.enable_vlan"))
    {
        char *vlanid = config_read_string("network.wan.vlan_id");

        //global_vlan, is_lan, vlan, tag, id, pri, cfi, forwarding_rule
        procwrite("/proc/eth1/mib_vlan", "1 0 1 1 %s 0 0 0", vlanid);  // change global vlan ID
        procwrite("/proc/rtk_vlan_support", "1");
    }
    else
        procwrite("/proc/rtk_vlan_support", "0");

    // ipv6 address
    if(config_item_active("network.ipv6.active"))
    {
        char *mode = config_read_string("network.ipv6.wan_mode");

        sysexec(true, "sysctl", "-w net.ipv6.conf.all.autoconf=1");
        sysexec(true, "sysctl", "-w net.ipv6.conf.all.accept_ra=0");
        sysexec(true, "sysctl", "-w net.ipv6.conf.default.autoconf=1");
        sysexec(true, "sysctl", "-w net.ipv6.conf.default.accept_ra=0");
  
        if(IS(mode, "dhcp"))
        {
        }
        else
        if(IS(mode, "pppoe"))
        {
            // dual stack IPv6
            if(IS(v4pwd,v6pwd) && IS(v4usr, v6usr))
            {
            }
            else
            {
                char *buf;
                const char *conf = "plugin rp-pppoe.so %s\n"
                                "user %s\n"
                                "password %s\n"
                                "usepeerdns\n"
                                "nolog\n"
                                "noipx\n"
                                "novj\n"
                                "nobsdcomp\n"
                                "noresolv\n"
                                "ktune\n"
                                "noipdefault\n"
                                "noip\n"
                                "+ipv6 ipv6cp-use-ipaddr\n"
                                "hide-password\n"
                                "lcp-echo-interval 20\n"
                                "lcp-echo-failure 3\n"
                                "noauth\n"
                                "persist\n"
                                "ifname pppv6\n"
                                "maxfail 0";

                asprintf(&buf, conf, "eth1", v6usr, v6pwd);

                write_textfile("/etc/pppd6.conf", buf, false);

                sysexec(true, "ip", "link set eth1 up");
                sysexec(false, "pppd", "file /etc/pppd6.conf");

                free(buf);
            }
        }
        else
        if(IS(mode, "static"))
        {
            const char *script = "ADDR1=$(ipaddr -6 show dev eth1 scope global | awk 'BEGIN {FS=\":| +\"; OFS=\":\"}{ if($2==\"inet6\") { print $3,$4,$5,$6; exit; } }')\n"
                                 "ADDR2=$(ipaddr -6 show dev br0 scope link | awk 'BEGIN {FS=\":| +\"; OFS=\":\"}{ if($2==\"inet6\") print $5,$6,$7,$8 }')\n"
                                 "ipaddr -6 add $ADDR1:$ADDR2 dev br0\n";

            sysexec(true, "ip", "addr -f inet6 add %s/%s dev eth1", config_read_string("network.ipv6.wan_addr"),
                                                            config_read_string("network.ipv6.wan_prefix"));

            sysexec(true, "ip", "route -6 add ::/0 dev eth1");
            sysexec(true, "ip", "route -6 add default gw %s dev eth1", config_read_string("network.ipv6.wan_gateway"));

            sysexec_shell(script);
        }

        sysexec(true, "ip", "link set eth1 up");
    }
}

void lan_start(bool startup)
{
    if(startup)
    {
        char *mac = config_read_string("network.lan.macaddr");
        char *gw = config_read_string("network.wan.gateway");

        // main port hwaddr
        sysexec(true, "ip", "link set eth0 address %s", mac);

        // add wireless bridges
        sysexec(true, "brctl", "addbr br0");
        sysexec(true, "brctl", "addbr br1");
        sysexec(true, "brctl", "addbr br2");

        sysexec(true, "brctl", "addif br0 eth0");

        // wireless bridges MAC address
        sysexec(true, "ip", "link set br0 address %s", mac);
        sysexec(true, "ip", "link set br1 address %s", config_read_string("network.secondary_wireless.macaddr"));
        sysexec(true, "ip", "link set br2 address %s", config_read_string("network.third_wireless.macaddr"));

        // bridge all LAN ports
        // bridged mode gateway set on LAN side
        if(IS(config_read_string("network.wan.mode"), "bridge"))
        {
            // set remaining ports MAC to the same address
            sysexec(true, "ip", "link set eth2 address %s", mac);
            sysexec(true, "ip", "link set eth3 address %s", mac);
            sysexec(true, "ip", "link set eth4 address %s", mac);

            // add remaining ports to the bridge
            sysexec(true, "brctl", "addif br0 eth2");
            sysexec(true, "brctl", "addif br0 eth3");
            sysexec(true, "brctl", "addif br0 eth4");

            // set them up
            sysexec(true, "ip", "link set eth2 up");
            sysexec(true, "ip", "link set eth3 up");
            sysexec(true, "ip", "link set eth4 up");

            if(!is_empty(gw))
            {
                sysexec(true, "ip", "link set br0 up");
                sysexec(true, "route", "del default");
                sysexec(true, "route", "add default gw %s dev br0", gw);
            }
        }

        sysexec(true, "ip", "link set eth0 up");
        sysexec(true, "ip", "link set br0 up");
        sysexec(true, "ip", "link set br1 up");
        sysexec(true, "ip", "link set br2 up");
        sysexec(true, "ip", "link set lo up");

        procwrite("/proc/sw_nat", "9");
    }

    sysexec(true, "ip", "-4 addr flush dev br0");
    sysexec(true, "ip", "-4 addr add %s/%s dev br0", config_read_string("network.lan.ipaddr"),
                                                     config_read_string("network.lan.netmask"));
}

void wireless_start(bool startup)
{
    struct hw_header hw;
    int channel;
    char *txrate;
    char *regulatory, *band, *opmode, *sysopmode;
    int rssi;
    int txpower = 0;

    if(config_item_active("network.wireless.active"))
    {
        FILE *cfg = fopen("/etc/Wireless/RTL8192CD.dat", "w");

        channel = atoi(config_read_string("network.wireless.channel"));
        txrate = config_read_string("network.wireless.txrate");
        band = config_read_string("network.wireless.band");
        opmode = config_read_string("network.wireless.opmode");
        sysopmode = config_read_string("network.wan.mode");
        txpower = atoi(config_read_string("network.wireless.txpower"));
        regulatory = config_read_string("network.wireless.regulatory");

        if(txpower>17)
            txpower = 0;

        rssi = atoi(config_read_string("network.wireless.min_signal"));
        rssi = (int)round((rssi*100)/140);
        if(rssi<0)
            rssi = 0;

        // root interface
        fprintf(cfg, "wlan0_disable_txpwrlmt=1\n");
        fprintf(cfg, "wlan0_led_type=7\n");
        fprintf(cfg, "wlan0_shortGI20M=1\n");
        fprintf(cfg, "wlan0_shortGI40M=1\n");
        fprintf(cfg, "wlan0_stbc=0\n");     // Space–time block coding
        fprintf(cfg, "wlan0_ampdu=1\n");    // Aggregated MAC Protocol Data Unit
        fprintf(cfg, "wlan0_amsdu=1\n");
        fprintf(cfg, "wlan0_disable_protection=1\n");
        fprintf(cfg, "wlan0_qos_enable=1\n");
        fprintf(cfg, "wlan0_coexist=0\n");
        fprintf(cfg, "wlan0_use40M=%d\n", config_item_active("network.wireless.40mhz_width"));
        fprintf(cfg, "wlan0_channel=%d\n", channel);

        if(config_item_active("network.wireless.isolation"))
        {
            fprintf(cfg, "wlan0_block_relay=1\n");
            fprintf(cfg, "wlan0-va1_block_relay=1\n");
            fprintf(cfg, "wlan0-va2_block_relay=1\n");
        }
        else
        {
            fprintf(cfg, "wlan0_block_relay=0\n");
            fprintf(cfg, "wlan0-va1_block_relay=0\n");
            fprintf(cfg, "wlan0-va2_block_relay=0\n");
        }

        if(IS(regulatory, "worldwide"))
            fprintf(cfg, "wlan0_regdomain=15\n");
        else
        if(IS(regulatory, "mkk"))
            fprintf(cfg, "wlan0_regdomain=6\n");
        else
        if(IS(regulatory, "fcc"))
            fprintf(cfg, "wlan0_regdomain=1\n");

        if(IS(txrate, "max"))
            fprintf(cfg, "wlan0_fixrate=0\n");
        else
        if(IS(txrate, "54"))
            fprintf(cfg, "wlan0_fixrate=12\n");
        else
        if(IS(txrate, "11"))
            fprintf(cfg, "wlan0_fixrate=4\n");

        if(channel < 5)
            fprintf(cfg, "wlan0_2ndchoffset=2\n");
        else
            fprintf(cfg, "wlan0_2ndchoffset=1\n");
       
        if(IS(opmode, "repeater"))
        {
            char *crypto = config_read_string("network.repeater_wireless.encryption");
            char *mac = strdup(config_read_string("network.primary_wireless.macaddr"));
            mac = remove_dots(mac);

            fprintf(cfg, "wlan0-vxd_hwaddr=%s\n", mac);
            fprintf(cfg, "wlan0-vxd_ssid=\"%s\"\n", config_read_string("network.repeater_wireless.ssid"));
            fprintf(cfg, "wlan0-vxd_passphrase=\"%s\"\n", config_read_string("network.repeater_wireless.password"));

            if(IS(crypto, "wpa2-aes"))
            {
                fprintf(cfg, "wlan0-vxd_psk_enable=2\n");
                fprintf(cfg, "wlan0-vxd_wpa_cipher=0\n");
                fprintf(cfg, "wlan0-vxd_wpa2_cipher=8\n");
                fprintf(cfg, "wlan0-vxd_encmode=4\n");
            }
            else
            if(IS(crypto, "wpa2-tkip"))
            {
                fprintf(cfg, "wlan0-vxd_psk_enable=2\n");
                fprintf(cfg, "wlan0-vxd_wpa_cipher=0\n");
                fprintf(cfg, "wlan0-vxd_wpa2_cipher=2\n");
                fprintf(cfg, "wlan0-vxd_encmode=4\n");
            }
            else
            if(IS(crypto, "wpa-aes"))
            {
                fprintf(cfg, "wlan0-vxd_psk_enable=1\n");
                fprintf(cfg, "wlan0-vxd_wpa_cipher=8\n");
                fprintf(cfg, "wlan0-vxd_wpa2_cipher=0\n");
                fprintf(cfg, "wlan0-vxd_encmode=2\n");
            }
            else
            if(IS(crypto, "wpa-tkip"))
            {
                fprintf(cfg, "wlan0-vxd_psk_enable=1\n");
                fprintf(cfg, "wlan0-vxd_wpa_cipher=2\n");
                fprintf(cfg, "wlan0-vxd_wpa2_cipher=0\n");
                fprintf(cfg, "wlan0-vxd_encmode=2\n");
            }
            else
            {
                // open network
                fprintf(cfg, "wlan0-vxd_encmode=0\n");
                fprintf(cfg, "wlan0-vxd_psk_enable=0\n");
                fprintf(cfg, "wlan0-vxd_wpa_cipher=0\n");
                fprintf(cfg, "wlan0-vxd_wpa2_cipher=0\n");
            }

            fprintf(cfg, "wlan0-vxd_opmode=1033\n");
        }

        if(config_item_active("network.primary_wireless.active"))
        {
            char *mac = strdup(config_read_string("network.primary_wireless.macaddr"));
            mac = remove_dots(mac);

            fprintf(cfg, "wlan0_opmode=16\n");
            fprintf(cfg, "wlan0_hwaddr=%s\n", mac);
            fprintf(cfg, "wlan0_ssid=\"%s\"\n", config_read_string("network.primary_wireless.ssid"));
            fprintf(cfg, "wlan0_vap_enable=1\n");

            if(IS(band, "b"))
                fprintf(cfg, "wlan0_band=1\n");  // B (non mixed)
            else
            if(IS(band, "bg"))
                fprintf(cfg, "wlan0_band=3\n");  // B/G (mixed mode)
            else
            if(IS(band, "bgn"))
                fprintf(cfg, "wlan0_band=11\n");  // B/G/N (mixed mode)
            else
            if(IS(band, "g"))
                fprintf(cfg, "wlan0_band=2\n");  // G Only (non mixed)
            else
            if(IS(band, "n"))
                fprintf(cfg, "wlan0_band=8\n");  // N Only (non mixed)

            if(config_item_active("network.wireless.threshold"))
                fprintf(cfg, "wlan0_sta_asoc_rssi_th=%d\n", rssi);
            else
                fprintf(cfg, "wlan0_sta_asoc_rssi_th=0\n");

            if(config_item_active("network.primary_wireless.hidden"))
                fprintf(cfg, "wlan0_hiddenAP=1\n");
            else
                fprintf(cfg, "wlan0_hiddenAP=0\n");

            if(!is_empty(config_read_string("network.primary_wireless.password")))
            {
                fprintf(cfg, "wlan0_passphrase=\"%s\"\n", config_read_string("network.primary_wireless.password"));

                char *crypto;
                if(IS(opmode, "repeater"))
                    crypto = config_read_string("network.repeater_wireless.encryption");
                else
                    crypto = config_read_string("network.wireless.encryption");

                if(IS(crypto, "wpa2-aes"))
                {
                    fprintf(cfg, "wlan0_psk_enable=2\n");
                    fprintf(cfg, "wlan0_wpa_cipher=0\n");
                    fprintf(cfg, "wlan0_wpa2_cipher=8\n");
                    fprintf(cfg, "wlan0_encmode=4\n");
                }
                else
                if(IS(crypto, "wpa2-tkip"))
                {
                    fprintf(cfg, "wlan0_psk_enable=2\n");
                    fprintf(cfg, "wlan0_wpa_cipher=0\n");
                    fprintf(cfg, "wlan0_wpa2_cipher=2\n");
                    fprintf(cfg, "wlan0_encmode=4\n");
                }
                else
                if(IS(crypto, "wpa-aes"))
                {
                    fprintf(cfg, "wlan0_psk_enable=1\n");
                    fprintf(cfg, "wlan0_wpa_cipher=8\n");
                    fprintf(cfg, "wlan0_wpa2_cipher=0\n");
                    fprintf(cfg, "wlan0_encmode=2\n");
                }
                else
                if(IS(crypto, "wpa-tkip"))
                {
                    fprintf(cfg, "wlan0_psk_enable=1\n");
                    fprintf(cfg, "wlan0_wpa_cipher=2\n");
                    fprintf(cfg, "wlan0_wpa2_cipher=0\n");
                    fprintf(cfg, "wlan0_encmode=2\n");
                }
            }
            else
            {
                fprintf(cfg, "wlan0_encmode=0\n");
                fprintf(cfg, "wlan0_psk_enable=0\n");
                fprintf(cfg, "wlan0_wpa_cipher=0\n");
                fprintf(cfg, "wlan0_wpa2_cipher=0\n");
            }

            free(mac);
        }

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        if(config_item_active("network.secondary_wireless.active"))
        {
            char *mac = strdup(config_read_string("network.secondary_wireless.macaddr"));
            mac = remove_dots(mac);

            fprintf(cfg, "wlan0-va1_opmode=16\n");
            fprintf(cfg, "wlan0-va1_hwaddr=%s\n", mac);
            fprintf(cfg, "wlan0-va1_ssid=\"%s\"\n", config_read_string("network.secondary_wireless.ssid"));
            fprintf(cfg, "wlan0-va1_vap_enable=1\n");

            if(IS(band, "b"))
                fprintf(cfg, "wlan0-va1_band=1\n");  // B
            else
            if(IS(band, "g"))
                fprintf(cfg, "wlan0-va1_band=3\n");  // B/G
            else
            if(IS(band, "n"))
                fprintf(cfg, "wlan0-va1_band=11\n");  // B/G/N

            if(config_item_active("network.wireless.threshold"))
                fprintf(cfg, "wlan0-va1_sta_asoc_rssi_th=%d\n", rssi);
            else
                fprintf(cfg, "wlan0-va1_sta_asoc_rssi_th=0\n");

            if(config_item_active("network.secondary_wireless.hidden"))
                fprintf(cfg, "wlan0-va1_hiddenAP=1\n");
            else
                fprintf(cfg, "wlan0-va1_hiddenAP=0\n");

            if(!is_empty(config_read_string("network.secondary_wireless.password")))
            {
                fprintf(cfg, "wlan0-va1_passphrase=\"%s\"\n", config_read_string("network.secondary_wireless.password"));

                char *crypto = config_read_string("network.wireless.encryption");

                if(IS(crypto, "wpa2-aes"))
                {
                    fprintf(cfg, "wlan0-va1_psk_enable=2\n");
                    fprintf(cfg, "wlan0-va1_wpa_cipher=0\n");
                    fprintf(cfg, "wlan0-va1_wpa2_cipher=8\n");
                    fprintf(cfg, "wlan0-va1_encmode=4\n");
                }
                else
                if(IS(crypto, "wpa2-tkip"))
                {
                    fprintf(cfg, "wlan0-va1_psk_enable=2\n");
                    fprintf(cfg, "wlan0-va1_wpa_cipher=0\n");
                    fprintf(cfg, "wlan0-va1_wpa2_cipher=2\n");
                    fprintf(cfg, "wlan0-va1_encmode=4\n");
                }
                else
                if(IS(crypto, "wpa-aes"))
                {
                    fprintf(cfg, "wlan0-va1_psk_enable=1\n");
                    fprintf(cfg, "wlan0-va1_wpa_cipher=8\n");
                    fprintf(cfg, "wlan0-va1_wpa2_cipher=0\n");
                    fprintf(cfg, "wlan0-va1_encmode=2\n");
                }
                else
                if(IS(crypto, "wpa-tkip"))
                {
                    fprintf(cfg, "wlan0-va1_psk_enable=1\n");
                    fprintf(cfg, "wlan0-va1_wpa_cipher=2\n");
                    fprintf(cfg, "wlan0-va1_wpa2_cipher=0\n");
                    fprintf(cfg, "wlan0-va1_encmode=2\n");
                }
            }
            else
            {
                fprintf(cfg, "wlan0-va1_encmode=0\n");
                fprintf(cfg, "wlan0-va1_psk_enable=0\n");
                fprintf(cfg, "wlan0-va1_wpa_cipher=0\n");
                fprintf(cfg, "wlan0-va1_wpa2_cipher=0\n");
            }
    
            free(mac);
        }

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        if(config_item_active("network.third_wireless.active"))
        {
            char *mac = strdup(config_read_string("network.third_wireless.macaddr"));
            mac = remove_dots(mac);

            fprintf(cfg, "wlan0-va2_opmode=16\n");
            fprintf(cfg, "wlan0-va2_hwaddr=%s\n", mac);
            fprintf(cfg, "wlan0-va2_ssid=\"%s\"\n", config_read_string("network.third_wireless.ssid"));
            fprintf(cfg, "wlan0-va2_vap_enable=1\n");

            if(IS(band, "b"))
                fprintf(cfg, "wlan0-va2_band=1\n");  // B
            else
            if(IS(band, "g"))
                fprintf(cfg, "wlan0-va2_band=3\n");  // B/G
            else
            if(IS(band, "n"))
                fprintf(cfg, "wlan0-va2_band=11\n");  // B/G/N

            if(config_item_active("network.wireless.threshold"))
                fprintf(cfg, "wlan0-va2_sta_asoc_rssi_th=%d\n", rssi);
            else
                fprintf(cfg, "wlan0-va2_sta_asoc_rssi_th=0\n");

            if(config_item_active("network.third_wireless.hidden"))
                fprintf(cfg, "wlan0-va2_hiddenAP=1\n");
            else
                fprintf(cfg, "wlan0-va2_hiddenAP=0\n");

            if(!is_empty(config_read_string("network.third_wireless.password")))
            {
                fprintf(cfg, "wlan0-va2_passphrase=\"%s\"\n", config_read_string("network.third_wireless.password"));

                char *crypto = config_read_string("network.wireless.encryption");

                if(IS(crypto, "wpa2-aes"))
                {
                    fprintf(cfg, "wlan0-va2_psk_enable=2\n");
                    fprintf(cfg, "wlan0-va2_wpa_cipher=0\n");
                    fprintf(cfg, "wlan0-va2_wpa2_cipher=8\n");
                    fprintf(cfg, "wlan0-va2_encmode=4\n");
                }
                else
                if(IS(crypto, "wpa2-tkip"))
                {
                    fprintf(cfg, "wlan0-va2_psk_enable=2\n");
                    fprintf(cfg, "wlan0-va2_wpa_cipher=0\n");
                    fprintf(cfg, "wlan0-va2_wpa2_cipher=2\n");
                    fprintf(cfg, "wlan0-va2_encmode=4\n");
                }
                else
                if(IS(crypto, "wpa-aes"))
                {
                    fprintf(cfg, "wlan0-va2_psk_enable=1\n");
                    fprintf(cfg, "wlan0-va2_wpa_cipher=8\n");
                    fprintf(cfg, "wlan0-va2_wpa2_cipher=0\n");
                    fprintf(cfg, "wlan0-va2_encmode=2\n");
                }
                else
                if(IS(crypto, "wpa-tkip"))
                {
                    fprintf(cfg, "wlan0-va2_psk_enable=1\n");
                    fprintf(cfg, "wlan0-va2_wpa_cipher=2\n");
                    fprintf(cfg, "wlan0-va2_wpa2_cipher=0\n");
                    fprintf(cfg, "wlan0-va2_encmode=2\n");
                }
            }
            else
            {
                fprintf(cfg, "wlan0-va2_encmode=0\n");
                fprintf(cfg, "wlan0-va2_psk_enable=0\n");
                fprintf(cfg, "wlan0-va2_wpa_cipher=0\n");
                fprintf(cfg, "wlan0-va2_wpa2_cipher=0\n");
            }
    
            free(mac);
        }

        if(read_hw_settings(&hw))
        {
            int lvl;

            fprintf(cfg, "wlan0_xcap=%d\n", hw.xCap);
            fprintf(cfg, "wlan0_tssi1=%d\n", hw.TSSI1);
            fprintf(cfg, "wlan0_tssi2=%d\n", hw.TSSI2);
            fprintf(cfg, "wlan0_ther=%d\n", hw.Ther);

            fprintf(cfg, "wlan0_pwrlevelCCK_A=");
            for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
            {
                lvl = hw.pwrlevelCCK_A[i];
                if(lvl>0 && txpower>0) lvl -= txpower;
                if(lvl<0) lvl = 0;

                fprintf(cfg, "%02x", lvl);
            }
            fprintf(cfg, "\n");

            fprintf(cfg, "wlan0_pwrlevelCCK_B=");
            for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
            {
                lvl = hw.pwrlevelCCK_B[i];
                if(lvl>0 && txpower>0) lvl -= txpower;
                if(lvl<0) lvl = 0;

                fprintf(cfg, "%02x", lvl);
            }
            fprintf(cfg, "\n");

            fprintf(cfg, "wlan0_pwrlevelHT40_1S_A=");
            for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
            {
                lvl = hw.pwrlevelHT40_1S_A[i];
                if(lvl>0 && txpower>0) lvl -= txpower;
                if(lvl<0) lvl = 0;

                fprintf(cfg, "%02x", lvl);
            }
            fprintf(cfg, "\n");

            fprintf(cfg, "wlan0_pwrlevelHT40_1S_B=");
            for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
            {
                lvl = hw.pwrlevelHT40_1S_B[i];
                if(lvl>0 && txpower>0) lvl -= txpower;
                if(lvl<0) lvl = 0;

                fprintf(cfg, "%02x", lvl);
            }
            fprintf(cfg, "\n");

            fprintf(cfg, "wlan0_pwrdiffHT40_2S=");
            for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
                fprintf(cfg, "%02x", hw.pwrdiffHT40_2S[i]);
            fprintf(cfg, "\n");

            fprintf(cfg, "wlan0_pwrdiffHT20=");
            for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
                fprintf(cfg, "%02x", hw.pwrdiffHT20[i]);
            fprintf(cfg, "\n");

            fprintf(cfg, "wlan0_pwrdiffOFDM=");
            for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
                fprintf(cfg, "%02x", hw.pwrdiffOFDM[i]);
            fprintf(cfg, "\n");
        }
        else
            DEBUG("Failed to read Wireless parameters!");

        fclose(cfg);

        if(startup)
        {
            if(IS(opmode, "repeater") || IS(sysopmode, "bridge"))
            {
                // put all interfaces in the same bridge
                sysexec(true, "brctl", "addif br0 %s", "wlan0-vxd");
                sysexec(true, "brctl", "addif br0 %s", "wlan0");
                sysexec(true, "brctl", "addif br0 %s", "wlan0-va1");
                sysexec(true, "brctl", "addif br0 %s", "wlan0-va2");
            }
            else
            {
                // add primary wireless to LAN bridge device
                sysexec(true, "brctl", "addif br0 %s", "wlan0");
                sysexec(true, "brctl", "addif br1 %s", "wlan0-va1");
                sysexec(true, "brctl", "addif br2 %s", "wlan0-va2");
            }
        }
        else
        {
            // tell driver to reload config
            sysexec(true, "iwpriv", "wlan0 cfgfile");

            sysexec(true, "ip", "link set %s down", "wlan0-va1");
            sysexec(true, "ip", "link set %s down", "wlan0-va2");
            sysexec(true, "ip", "link set %s down", "wlan0-vxd");
            sysexec(true, "ip", "link set %s down", "wlan0");
        }

        if(config_item_active("network.primary_wireless.active"))
            sysexec(true, "ip", "link set %s up", "wlan0");

        sysexec(true, "ip", "-4 addr flush dev %s", "br1");
        if(config_item_active("network.secondary_wireless.active"))
        {
            // set secondary interface IP address
            sysexec(true, "ip", "addr add %s/%s dev %s", config_read_string("network.secondary_wireless.ipaddr"),
                                                        config_read_string("network.secondary_wireless.netmask"),
                                                        "br1");

            sysexec(true, "ip", "link set %s up", "wlan0-va1");
        }
        else
            sysexec(true, "ip", "link set %s down", "wlan0-va1");

        sysexec(true, "ip", "-4 addr flush dev %s", "br2");
        if(config_item_active("network.third_wireless.active"))
        {
            // set third interface IP address
            sysexec(true, "ip", "addr add %s/%s dev %s", config_read_string("network.third_wireless.ipaddr"),
                                                        config_read_string("network.third_wireless.netmask"),
                                                        "br2");

            sysexec(true, "ip", "link set %s up", "wlan0-va2");
        }
        else
            sysexec(true, "ip", "link set %s down", "wlan0-va2");

        if(IS(opmode, "repeater"))
            sysexec(true, "ip", "link set %s up", "wlan0-vxd");


        procwrite("/proc/wlan0/led", "3");
    }
    else
        procwrite("/proc/wlan0/led", "0");
}

void syslog_start()
{
    sysexec(false, "syslogd", "-C");
    sysexec(false, "klogd", "");
}

void cron_start(bool startup)
{
    FILE *f;

    f = fopen("/etc/crontabs/root", "w");

    cJSON *next = config_get_node("timecontrol.primary_wireless.rules");
    char *blacklist = config_read_string("timecontrol.primary_wireless.blacklist");

    if(config_item_active("network.primary_wireless.active"))
    {
        if(next->type == cJSON_Array)
        {
            for(int y=0; y<cJSON_GetArraySize(next); y++)
            {
                cJSON *array = cJSON_GetArrayItem(next, y);

                char *h_start = cJSON_GetObjectItem(array, "hour_start")->valuestring;
                char *m_start = cJSON_GetObjectItem(array, "minute_start")->valuestring;
                char *h_end = cJSON_GetObjectItem(array, "hour_end")->valuestring;
                char *m_end = cJSON_GetObjectItem(array, "minute_end")->valuestring;
                char *day = cJSON_GetObjectItem(array, "day")->valuestring;

                if(IS(day, "Mon")) day="1";
                if(IS(day, "Tue")) day="2";
                if(IS(day, "Wed")) day="3";
                if(IS(day, "Thu")) day="4";
                if(IS(day, "Fri")) day="5";
                if(IS(day, "Sat")) day="6";
                if(IS(day, "Sun")) day="0";

                DEBUG("%s", h_start);

                if(IS(blacklist, "true"))
                {
                    fprintf(f, "%s %s * * %s iplink set %s down\n", m_start, h_start, day, "wlan0");
                    fprintf(f, "%s %s * * %s iplink set %s up\n", m_end, h_end, day, "wlan0"); 
                }
                else
                {
                    fprintf(f, "%s %s * * %s iplink set %s up\n", m_start, h_start, day, "wlan0");
                    fprintf(f, "%s %s * * %s iplink set %s down\n", m_end, h_end, day, "wlan0"); 
                }
            }
        }
    }

    next = config_get_node("timecontrol.secondary_wireless.rules");
    blacklist = config_read_string("timecontrol.secondary_wireless.blacklist");

    if(config_item_active("network.secondary_wireless.active"))
    {
        if(next->type == cJSON_Array)
        {
            for(int y=0; y<cJSON_GetArraySize(next); y++)
            {
                cJSON *array = cJSON_GetArrayItem(next, y);

                char *h_start = cJSON_GetObjectItem(array, "hour_start")->valuestring;
                char *m_start = cJSON_GetObjectItem(array, "minute_start")->valuestring;
                char *h_end = cJSON_GetObjectItem(array, "hour_end")->valuestring;
                char *m_end = cJSON_GetObjectItem(array, "minute_end")->valuestring;
                char *day = cJSON_GetObjectItem(array, "day")->valuestring;

                if(IS(day, "Mon")) day="1";
                if(IS(day, "Tue")) day="2";
                if(IS(day, "Wed")) day="3";
                if(IS(day, "Thu")) day="4";
                if(IS(day, "Fri")) day="5";
                if(IS(day, "Sat")) day="6";
                if(IS(day, "Sun")) day="0";

                DEBUG("%s", h_start);

                if(IS(blacklist, "true"))
                {
                    fprintf(f, "%s %s * * %s iplink set %s down\n", m_start, h_start, day, "wlan0-va1");
                    fprintf(f, "%s %s * * %s iplink set %s up\n", m_end, h_end, day, "wlan0-va1"); 
                }
                else
                {
                    fprintf(f, "%s %s * * %s iplink set %s up\n", m_start, h_start, day, "wlan0-va1");
                    fprintf(f, "%s %s * * %s iplink set %s down\n", m_end, h_end, day, "wlan0-va1"); 
                }
            }
        }
    }

    next = config_get_node("timecontrol.third_wireless.rules");
    blacklist = config_read_string("timecontrol.third_wireless.blacklist");

    if(config_item_active("network.third_wireless.active"))
    {
        if(next->type == cJSON_Array)
        {
            for(int y=0; y<cJSON_GetArraySize(next); y++)
            {
                cJSON *array = cJSON_GetArrayItem(next, y);

                char *h_start = cJSON_GetObjectItem(array, "hour_start")->valuestring;
                char *m_start = cJSON_GetObjectItem(array, "minute_start")->valuestring;
                char *h_end = cJSON_GetObjectItem(array, "hour_end")->valuestring;
                char *m_end = cJSON_GetObjectItem(array, "minute_end")->valuestring;
                char *day = cJSON_GetObjectItem(array, "day")->valuestring;

                if(IS(day, "Mon")) day="1";
                if(IS(day, "Tue")) day="2";
                if(IS(day, "Wed")) day="3";
                if(IS(day, "Thu")) day="4";
                if(IS(day, "Fri")) day="5";
                if(IS(day, "Sat")) day="6";
                if(IS(day, "Sun")) day="0";

                DEBUG("%s", h_start);

                if(IS(blacklist, "true"))
                {
                    fprintf(f, "%s %s * * %s iplink set %s down\n", m_start, h_start, day, "wlan0-va2");
                    fprintf(f, "%s %s * * %s iplink set %s up\n", m_end, h_end, day, "wlan0-va2"); 
                }
                else
                {
                    fprintf(f, "%s %s * * %s iplink set %s up\n", m_start, h_start, day, "wlan0-va2");
                    fprintf(f, "%s %s * * %s iplink set %s down\n", m_end, h_end, day, "wlan0-va2"); 
                }
            }
        }
    }

    if(config_item_active("system.watchdog.active"))
    {
        char *host = config_read_string("system.watchdog.ipaddr");
        int timeout = atoi(config_read_string("system.watchdog.timeout"));

        fprintf(f, "*/%d * * * * ping -w 5 -c 3 %s || reboot -f\n", timeout, host);
    }

    fclose(f);

    if(!startup)
        syskill("crond");

    sysexec(false, "crond", "-c /etc/crontabs");
}

void ntpd_start(bool startup)
{
    FILE *f;
    char *zone = strdup(config_read_string("system.timezone"));
    bool dst = config_item_active("system.timezonedst");

    if(dst)
        zone[3]--;  // TODO

    f = fopen("/etc/TZ", "w");
    fputs(zone, f);
    fputs("\n", f);
    fflush(f);
    fclose(f);

    if(!startup)
        syskill("ntpd");

    sysexec_shell("ntpd -p %s -p %s -p %s -p %s >/dev/null 2>&1 &", config_read_string("system.timeservers.server1"),
                                                                    config_read_string("system.timeservers.server2"),
                                                                    config_read_string("system.timeservers.server3"),
                                                                    config_read_string("system.timeservers.server4"));

    free(zone);
}

void dropbear_start()
{
    if(config_item_active("remoteshell.active"))
    {
        char *rsa = config_read_string("remoteshell.key_rsa");
        char *dss = config_read_string("remoteshell.key_dss");
        char *ecdsa = config_read_string("remoteshell.key_ecdsa");
        char *buf, *network;
        size_t size;
        FILE *f;

        if(is_empty(rsa))
        {
            sysexec_shell("dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key");
            size = read_file(&rsa, "/etc/dropbear/dropbear_rsa_host_key");

            if(size)
            {
                buf = (char *)malloc(Base64encode_len(size));
                Base64encode(buf, rsa, size);

                config_write_string("remoteshell.key_rsa", buf);
                free(buf);
                free(rsa);
            }

            config_save(true);
        }
        else
        {
            size = Base64decode_len(rsa);
            if(size)
            {
                buf = (char *)malloc(size);
                Base64decode(buf, rsa);

                f = fopen("/etc/dropbear/dropbear_rsa_host_key", "wb");
                fwrite(buf, size, 1, f);
                fclose(f);

                free(buf);
            }
        }

        if(is_empty(dss))
        {
            sysexec_shell("dropbearkey -t dss -f /etc/dropbear/dropbear_dss_host_key");
            size = read_file(&dss, "/etc/dropbear/dropbear_dss_host_key");

            if(size)
            {
                buf = (char *)malloc(Base64encode_len(size));
                Base64encode(buf, dss, size);

                config_write_string("remoteshell.key_dss", buf);
                free(buf);
                free(dss);
            }

            config_save(true);
        }
        else
        {
            size = Base64decode_len(dss);
            if(size)
            {
                buf = (char *)malloc(size);
                Base64decode(buf, dss);

                f = fopen("/etc/dropbear/dropbear_dss_host_key", "wb");
                fwrite(buf, size, 1, f);
                fclose(f);

                free(buf);
            }
        }

        if(is_empty(ecdsa))
        {
            sysexec_shell("dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key");
            size = read_file(&ecdsa, "/etc/dropbear/dropbear_ecdsa_host_key");

            if(size)
            {
                buf = (char *)malloc(Base64encode_len(size));
                Base64encode(buf, ecdsa, size);

                config_write_string("remoteshell.key_ecdsa", buf);
                free(buf);
                free(ecdsa);
            }

            config_save(true);
        }
        else
        {
            size = Base64decode_len(ecdsa);
            if(size)
            {
                buf = (char *)malloc(size);
                Base64decode(buf, ecdsa);

                f = fopen("/etc/dropbear/dropbear_ecdsa_host_key", "wb");
                fwrite(buf, size, 1, f);
                fclose(f);

                free(buf);
            }
        }

        network = config_read_string("remoteshell.network");

        if(IS(network, "lan"))
            sysexec(true, "iptables", "-t filter -A services-inbound -i br+ -m connlimit ! --connlimit-above 2 --connlimit-mask 32 -p tcp --dport 22 -j ACCEPT");
        else
        if(IS(network, "wan"))
            sysexec(true, "iptables", "-t filter -A services-inbound -i eth1 -m connlimit ! --connlimit-above 2 --connlimit-mask 32 -p tcp --dport 22 -j ACCEPT");
        else
        if(IS(network, "lan+wan"))
            sysexec(true, "iptables", "-t filter -A services-inbound -m connlimit ! --connlimit-above 2 --connlimit-mask 32 -p tcp --dport 22 -j ACCEPT");

        sysexec(true, "dropbear", "-p 0.0.0.0:22");
    }
}

void openvpn_start(bool startup)
{
    size_t size;
    FILE *f;

    if(config_item_active("vpn.active"))
    {
        char *mode = config_read_string("vpn.mode");
        char *key = config_read_string("vpn.statickey");
        char *listen_port = config_read_string("vpn.listen_port");
        char *buf;

        if(is_empty(key))
        {
            sysexec(true, "openvpn", "--genkey --secret /etc/static.key");
            size = read_file(&key, "/etc/static.key");

            // save file content afer generating it
            if(size)
            {
                buf = (char *)malloc(Base64encode_len(size));
                Base64encode(buf, key, size);

                config_write_string("vpn.statickey", buf);
                free(buf);
                free(key);
            }

            config_save(true);
        }
        else
        {
            // file already generated, load it
            size = Base64decode_len(key);
            if(size)
            {
                buf = (char *)malloc(size);
                Base64decode(buf, key);

                f = fopen("/etc/static.key", "wb");
                fwrite(buf, size, 1, f);
                fclose(f);

                free(buf);
            }
        }
    }
}

void webserver_start(bool startup)
{
    char *webport = config_read_string("system.httpd_port");

    sysexec(true, "iptables", "-F webadmin-service");
    if(config_item_active("firewall.basic.wanddos"))
        sysexec(true, "iptables", "-t filter -A webadmin-service -p tcp --syn --dport 80 -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset");
    sysexec(true, "iptables", "-t filter -A webadmin-service -i br0 -p tcp --dport %s -j ACCEPT", webport);

    if(config_item_active("firewall.basic.wanaccess"))
        sysexec(true, "iptables", "-t filter -A webadmin-service -p tcp --dport %s -j ACCEPT", webport);

    if(!startup)
    {
        sysexec_shell("sleep 10 && killall -9 httpd && httpd -c /etc/httpd.conf -p 0.0.0.0:%s >/dev/null 2>&1 &", webport);
    }
    else
        sysexec(false, "httpd", "-c /etc/httpd.conf -p 0.0.0.0:%s", webport);
}

void qos_start()
{
    char *clearqos = "tc qdisc del dev ifb0 root >/dev/null 2>&1\n"
                     "tc qdisc del dev br0 root >/dev/null 2>&1\n"
                     "tc qdisc del dev br1 root >/dev/null 2>&1\n"
                     "tc qdisc del dev br2 root >/dev/null 2>&1\n";

    sysexec(true, "ip", "link set ifb0 up");
     
    sysexec_shell(clearqos);
    sysexec_shell("tc qdisc add dev ifb0 root handle 1: htb");
    sysexec_shell("tc qdisc add dev br0 root handle 1: htb");
    sysexec_shell("tc qdisc add dev br1 root handle 1: htb");
    sysexec_shell("tc qdisc add dev br2 root handle 1: htb");
    procwrite("/proc/fast_nat", "1");

    char *primary_up = config_read_string("network.qos.primary_upload");
    char *primary_down = config_read_string("network.qos.primary_download");
    char *secondary_up = config_read_string("network.qos.secondary_upload");
    char *secondary_down = config_read_string("network.qos.secondary_download");
    char *third_up = config_read_string("network.qos.third_upload");
    char *third_down = config_read_string("network.qos.third_download");

    // ingress (upload)
    sysexec_shell("tc qdisc add dev br0 handle ffff ingress");
    sysexec_shell("tc filter add dev br0 parent ffff: protocol ip u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev ifb0");

    // ingress (upload)
    sysexec_shell("tc qdisc add dev br1 handle ffff ingress");
    sysexec_shell("tc filter add dev br1 parent ffff: protocol ip u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev ifb0");

    // ingress (upload)
    sysexec_shell("tc qdisc add dev br2 handle ffff ingress");
    sysexec_shell("tc filter add dev br2 parent ffff: protocol ip u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev ifb0");


    cJSON *next = config_get_node("network.dhcp.leases");

    // only single depth array is allowed
    int class=10;
    if(next->type == cJSON_Array)
    {
        for(int y=0; y<cJSON_GetArraySize(next); y++)
        {
            cJSON *array = cJSON_GetArrayItem(next, y);

            char *active = cJSON_GetObjectItem(array, "qos_active")->valuestring;
            char *ip = cJSON_GetObjectItem(array, "ipaddr")->valuestring;
            char *iface = cJSON_GetObjectItem(array, "iface")->valuestring;
            bool prio = cJSON_GetObjectItem(array, "priority")->valuestring;
            int download = atoi(cJSON_GetObjectItem(array, "download")->valuestring);
            int upload = atoi(cJSON_GetObjectItem(array, "upload")->valuestring);

            if(IS(active, "true"))
            {
                sysexec_shell("tc class add dev ifb0 parent 1: classid 1:%d htb rate %dkbit", class, upload);
                sysexec_shell("tc filter add dev ifb0 protocol ip parent 1:0 prio 1 u32 match ip src %s flowid 1:%d", ip, class);

                sysexec_shell("tc class add dev %s parent 1: classid 1:%d htb rate %dkbit", iface, class, download);
                sysexec_shell("tc filter add dev %s protocol ip parent 1:0 prio 1 u32 match ip dst %s flowid 1:%d", iface, ip, class);

                if(prio)
                {
                    sysexec(true, "tc", "qdisc add dev %s parent 1:%d handle %d: sfq perturb 10", iface, class, class);
                    sysexec(true, "tc", "qdisc add dev ifb0 parent 1:%d handle %d: sfq perturb 10", class, class);
                }

                class+=2;
            }
        }

        if(class>=12)
            procwrite("/proc/fast_nat", "0");
    }


    if(config_item_active("network.primary_wireless.active"))
    {
        if(!is_empty(primary_up) && !is_empty(primary_down))
        {
            in_addr_t addr = a_to_hl(config_read_string("network.lan.ipaddr"));
            in_addr_t mask = a_to_hl(config_read_string("network.lan.netmask"));
            struct in_addr ip;

            ip.s_addr = htonl(addr&mask);

            sysexec_shell("tc class add dev ifb0 parent 1: classid 1:9999 htb rate %skbit", primary_up);
            sysexec_shell("tc class add dev br0 parent 1: classid 1:9999 htb rate %skbit", primary_down);

            sysexec_shell("tc filter add dev ifb0 protocol ip parent 1:0 prio 5 u32 match ip src %s/%s flowid 1:9999", inet_ntoa(ip), config_read_string("network.lan.netmask"));
            sysexec_shell("tc filter add dev br0 protocol ip parent 1:0 prio 5 u32 match ip dst %s/%s flowid 1:9999", inet_ntoa(ip), config_read_string("network.lan.netmask"));

            procwrite("/proc/fast_nat", "0");
        }
    }
    if(config_item_active("network.secondary_wireless.active"))
    {
        if(!is_empty(secondary_up) && !is_empty(secondary_down))
        {
            in_addr_t addr = a_to_hl(config_read_string("network.secondary_wireless.ipaddr"));
            in_addr_t mask = a_to_hl(config_read_string("network.secondary_wireless.netmask"));
            struct in_addr ip;

            ip.s_addr = htonl(addr&mask);

            sysexec_shell("tc class add dev ifb0 parent 1: classid 1:9998 htb rate %skbit", secondary_up);
            sysexec_shell("tc class add dev br1 parent 1: classid 1:9998 htb rate %skbit", secondary_down);

            sysexec_shell("tc filter add dev ifb0 protocol ip parent 1:0 prio 5 u32 match ip src %s/%s flowid 1:9998", inet_ntoa(ip), config_read_string("network.secondary_wireless.netmask"));
            sysexec_shell("tc filter add dev br1 protocol ip parent 1:0 prio 5 u32 match ip dst %s/%s flowid 1:9998", inet_ntoa(ip), config_read_string("network.secondary_wireless.netmask"));

            procwrite("/proc/fast_nat", "0");
        }
    }
    if(config_item_active("network.third_wireless.active"))
    {
        if(!is_empty(third_up) && !is_empty(third_down))
        {
            in_addr_t addr = a_to_hl(config_read_string("network.third_wireless.ipaddr"));
            in_addr_t mask = a_to_hl(config_read_string("network.third_wireless.netmask"));
            struct in_addr ip;

            ip.s_addr = htonl(addr&mask);

            sysexec_shell("tc class add dev ifb0 parent 1: classid 1:9997 htb rate %skbit", third_up);
            sysexec_shell("tc class add dev br2 parent 1: classid 1:9997 htb rate %skbit", third_down);

            sysexec_shell("tc filter add dev ifb0 protocol ip parent 1:0 prio 5 u32 match ip src %s/%s flowid 1:9997", inet_ntoa(ip), config_read_string("network.third_wireless.netmask"));
            sysexec_shell("tc filter add dev br2 protocol ip parent 1:0 prio 5 u32 match ip dst %s/%s flowid 1:9997", inet_ntoa(ip), config_read_string("network.third_wireless.netmask"));

            procwrite("/proc/fast_nat", "0");
        }
    }
}

//! executed by inittab
void sysinit_main(int argc, char **argv)
{
    // system led
    procwrite("/proc/gpio", "2");

    // set approximate date
    sysexec(false, "date", "-s 2018-01-01");

    sysctlwrite("kernel.printk", 0);

    // needed devices symlinks
    symlink("/proc/self/fd","/dev/fd");
    symlink("fd/0","/dev/stdin");
    symlink("fd/1","/dev/stdout");
    symlink("fd/2","/dev/stderr");
    symlink("/proc/kcore","/dev/core");

    check_mtdconfig();

    config_open();

    DEBUG("run services");

    syslog_start();         DEBUG("syslog done");
    firewall_start(true);   DEBUG("firewall ipv4 done");
    firewall6_start(true);  DEBUG("firewall ipv6 done");
    portforward_start();    DEBUG("portforward done");
    lan_start(true);        DEBUG("lan done");
    wan_start(true);        DEBUG("wan done");
    wireless_start(true);   DEBUG("wireless done");
    dnsmasq_start(true);    DEBUG("dnsmasq done");
    cron_start(true);       DEBUG("cron done");
    ntpd_start(true);       DEBUG("ntpd done");
    qos_start();            DEBUG("qos done");
    webserver_start(true);  DEBUG("webserver done");
    miniupnpd_start();      DEBUG("miniupnpd done");
    dropbear_start();       DEBUG("dropbear done");

    DEBUG("end services");

    config_close();
}
