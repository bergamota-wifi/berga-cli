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

////////////////////////////////////
//
//  IPv6 related only code!
//
////////////////////////////////////

void dhcp6c_lease_command(char *cmd)
{
    char *reason = getenv("REASON");
    char *dns = getenv("new_domain_name_servers");

    if(IS(reason, "NBI"))
    {
        char *token;
        char server[256];

        // dns servers from dhcp environment
        while((token = strsep(&dns," ")))
        {
            snprintf(server, sizeof(server), "nameserver %s\n", token);
            concat_textfile("/etc/resolv.dnsmasq", server);
        }
    }
}
