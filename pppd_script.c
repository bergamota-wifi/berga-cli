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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utils.h"

void pppd_script_command(int argc, char **argv)
{
    char *gateway = argv[5];
    //char *gateway = argv[6];

    char *ipaddr = getenv("IPLOCAL");
    char *iface = getenv("IFNAME");
    char *cmd = basename(argv[0]);

    config_open();

    if(IS(cmd, "ip-down"))
    {
        sysexec_shell("ip route del %s dev %s src %s table main", gateway, iface, ipaddr);

        // flush old records
        sysexec_shell("ip -4 route flush dev %s", iface);
        sysexec_shell("ip -4 route flush table wan1");

        sysexec_shell("ip", "rule del from %s table wan1", ipaddr);
        sysexec_shell("ip", "rule del fwmark 1 table wan1");

        sysexec_shell("iptables -D output-masq -t nat -o %s -j SNAT --to-source %s", iface, ipaddr);

        if(config_item_active("network.ipv6.active"))
            syskill("dhclient");
    }
    else
    if(IS(cmd, "ipv6-down"))
    {
        //if(config_item_active("network.ipv6.active"))
        //    syskill("dhclient");
    }
    else
    if(IS(cmd, "ipv6-up"))
    {
        if(config_item_active("network.ipv6.active"))
        {
            // grab IPv6 PD
            //sysexec_shell("sleep 10 && dhclient -6 -P -sf /usr/bin/ipv6_pppoe.sh -nw %s >/dev/null 2>&1 &", iface);
        }
    }
    else
    if(IS(cmd, "ip-up"))
    {
        char *dns1 = getenv("DNS1");
        char *dns2 = getenv("DNS2");
        char *dns3 = NULL;

        unlink("/etc/resolv.dnsmasq");

        if(config_item_active("network.dns.active"))
        {
            dns1 = config_read_string("network.dns.dns1");
            dns2 = config_read_string("network.dns.dns2");
            dns3 = config_read_string("network.dns.dns3");
        }

        if(!is_empty(dns1))
            save_textfile("/etc/resolv.dnsmasq", "nameserver %s\n", dns1);
        if(!is_empty(dns2))
            concat_textfile("/etc/resolv.dnsmasq", "nameserver %s\n", dns2);
        if(!is_empty(dns3))
            concat_textfile("/etc/resolv.dnsmasq", "nameserver %s\n", dns3);

        // ipv6 address
        if(config_item_active("network.ipv6.active"))
        {
            // dual stack grab IPv6 PD
            //sysexec_shell("sleep 10 && dhclient -6 -P -sf /usr/bin/ipv6_pppoe.sh -nw %s >/dev/null 2>&1 &", iface);
        }

        sleep(5);

        // single outgoing route
#if 1
        sysexec_shell("iplink set %s up", iface);
        sysexec_shell("route del default");
        sysexec_shell("route add default gw %s dev %s", gateway, iface);
        //sysexec_shell("ip route replace default table main via %s dev %s", gateway, iface);

        sysexec_shell("ip route flush cache");
        sysexec_shell("iptables -F output-masq -t nat");

        if(!config_item_active("network.wan.disable_nat"))
            sysexec_shell("iptables -A output-masq -t nat -o %s -j SNAT --to-source %s", iface, ipaddr);
#else
        // multiple gateway support
        struct in_addr h_addr, h_netmask, res;

        // network calc
        inet_aton(config_read_string("network.lan.ipaddr"), &h_addr);
        inet_aton(config_read_string("network.lan.netmask"), &h_netmask);
        res.s_addr = htonl(ntohl(h_addr.s_addr) & ntohl(h_netmask.s_addr));

        // flush old records
        sysexec_shell("ip route flush dev %s", iface);
        sysexec_shell("ip route flush table wan1");

        // main table route
        sysexec_shell("ip route add %s dev %s src %s table main", gateway, iface, ipaddr);

        // wan1 table rule
        sysexec_shell("ip route add %s dev %s src %s table wan1", ipaddr, iface, ipaddr);    // single IP dst route
        sysexec_shell("ip route add default via %s dev %s table wan1", gateway, iface);

        // packet mark
        sysexec_shell("ip rule add from %s table wan1", ipaddr);
        sysexec_shell("ip rule add fwmark 1 table wan1");

        // local packet routing to outgoing route
        sysexec_shell("ip route add %s/%s dev br0 src %s table wan1", inet_ntoa(res),
                                                                      config_read_string("network.lan.netmask"),
                                                                      config_read_string("network.lan.ipaddr"));

        // default local machine route
        sysexec_shell("route del default");
        sysexec_shell("route add default gw %s dev %s", gateway, iface);
        //sysexec_shell("ip route replace default table main via %s dev %s", gateway, iface);
#endif
        // fork a ddns update process
        sysexec_shell("sleep 10 && berga-cli ddnsupdate >/dev/null 2>&1 &");
    }

    config_close();
}
