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

void udhcpc_lease_command(char *cmd)
{
    char *iface = getenv("interface");
    char *router = getenv("router");
    char *netmask = getenv("subnet");
    char *ipaddr = getenv("ip");
    char *dns = getenv("dns");

    config_open();

    if(IS(cmd, "deconfig"))
    {
        // remove any associated IP address
        sysexec(true, "ip", "-4 addr flush %s", iface);
        sysexec(true, "ip", "-4 route flush dev %s", iface);
        sysexec(true, "ip", "-4 route flush table wan1");

        if(ipaddr)
            sysexec(true, "iptables", "-D output-masq -t nat -o %s -j SNAT --to-source %s", iface, ipaddr);
    }
    else
    if(IS(cmd, "bound") || IS(cmd, "renew"))
    {
        char *token;
        char server[256];

        unlink("/etc/resolv.dnsmasq");

        // write dns servers
        if(config_item_active("network.dns.active"))
        {
            char *dns1 = config_read_string("network.dns.dns1");
            char *dns2 = config_read_string("network.dns.dns2");
            char *dns3 = config_read_string("network.dns.dns3");

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
        else
        {
            // dns servers from dhcp environment
            while((token = strsep(&dns," ")))
            {
                snprintf(server, sizeof(server), "nameserver %s\n", token);
                write_textfile("/etc/resolv.dnsmasq", server, true);
            }
        }

        // single outgoing route
#if 1
        sysexec(true, "ip", "-4 addr flush dev %s", iface);
        sysexec(true, "ip", "-4 addr add %s/%s dev %s", ipaddr, netmask, iface);
        sysexec(true, "ip", "-4 route replace default table main via %s dev %s", router, iface);

        sysexec(true, "ip", "-4 route flush cache");
        sysexec(true, "iptables", "-F output-masq -t nat");

        if(!config_item_active("network.wan.disable_nat"))
            sysexec(true, "iptables", "-A output-masq -t nat -o %s -j SNAT --to-source %s", iface, ipaddr);
#else
        // multiple gateway support
        struct in_addr h_addr, h_netmask, res;
        char *bcast = getenv("broadcast");

        // network calc
        inet_aton(config_read_string("network.lan.ipaddr"), &h_addr);
        inet_aton(config_read_string("network.lan.netmask"), &h_netmask);
        res.s_addr = htonl(ntohl(h_addr.s_addr) & ntohl(h_netmask.s_addr));

        // add interface IP address
        sysexec(true, "ip", "addr flush %s", iface);
        sysexec(true, "ip", "addr add %s/%s broadcast %s dev %s", ipaddr, netmask, bcast, iface);

        // flush old records
        sysexec(true, "ip", "route flush dev %s", iface);
        sysexec(true, "ip", "route flush table wan1");

        // main table route
        sysexec(true, "ip", "route add %s dev %s src %s table main", router, iface, ipaddr);

        // wan1 table rule
        sysexec(true, "ip", "route add %s dev %s src %s table wan1", ipaddr, iface, ipaddr);    // single IP dst route
        sysexec(true, "ip", "route add default via %s dev %s table wan1", router, iface);

        // packet mark
        sysexec(true, "ip", "rule add from %s table wan1", ipaddr);
        sysexec(true, "ip", "rule add fwmark 1 table wan1");

        /////////// local packet routing to outgoing route
        sysexec(true, "ip", "route add %s/%s dev br0 src %s table wan1", inet_ntoa(res),
                                                                      config_read_string("network.lan.netmask"),
                                                                      config_read_string("network.lan.ipaddr"));
        ///////////

        // default local machine route
        //sysexec(true, "ip", "route replace default table main via %s dev %s", router, iface);
        sysexec(true, "route", "del default");
        sysexec(true, "route", "add default gw %s dev %s", router, iface);
#endif
    }
    
    config_close();
}
