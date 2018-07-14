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

#include "utils.h"
#include "ddns.h"
#include "base64.h"

/*
 * 
 */
int ddns_main(int argc, char** argv)
{
    // TODO: put a wget task into crontab file

    config_open();

    if(config_item_active("ddns.active"))
    {
        char *user, *pass, *host, *service;
        char *buf, in[1024];

        user = config_read_string("ddns.username");
        pass = config_read_string("ddns.password");
        host = config_read_string("ddns.domain");
        service = config_read_string("ddns.service");

        snprintf(in, sizeof(in), "%s:%s", user, pass);

        if(IS(service, "no-ip"))
            asprintf(&buf, "https://dynupdate.no-ip.com/nic/update?hostname=%s", host);
        else
        if(IS(service, "dyndns"))
            asprintf(&buf, "https://members.dyndns.org/nic/update?hostname=%s", host);
        else
        if(IS(service, "changeip"))
            asprintf(&buf, "https://nic.changeip.com/nic/update?u=%s&p=%s&hostname=%s", user, pass, host);
        else
        if(IS(service, "winco"))
            asprintf(&buf, "http://members.ddns.com.br/nic/update?hostname=%s", host);
    }

    config_close();

    return(EXIT_SUCCESS);
}