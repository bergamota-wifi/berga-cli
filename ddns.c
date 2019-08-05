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
#include <curl/curl.h>

#include "utils.h"
#include "ddns.h"
#include "base64.h"

/*
 *
 */
int ddns_main(int argc, char** argv)
{
    CURL *handle;
    CURLcode res;

    config_open();

    if(config_item_active("ddns.active"))
    {
        DEBUG("Running ddns update code...");

        handle = curl_easy_init();

        if(handle)
        {
            char *user, *pass, *host, *service, *token;
            char *buf, in[1024];

            FILE *devnull = fopen("/dev/null", "w+");

            user = config_read_string("ddns.username");
            pass = config_read_string("ddns.password");
            host = config_read_string("ddns.domain");
            service = config_read_string("ddns.service");
            token = config_read_string("ddns.token");

            curl_easy_setopt(handle, CURLOPT_HEADER, 0);
            curl_easy_setopt(handle, CURLOPT_VERBOSE, 1);
            curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0);
            curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0);
            curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1);

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
                asprintf(&buf, "https://members.ddns.com.br/nic/update?hostname=%s", host);
            else
            if(IS(service, "duckdns"))
                asprintf(&buf, "https://www.duckdns.org/update?domains=%s&token=%s", host, token);

            curl_easy_setopt(handle, CURLOPT_URL, buf);

            if(!is_empty(user) && !is_empty(pass))
            {
                snprintf(in, sizeof(in), "%s:%s", user, pass);

                curl_easy_setopt(handle, CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);
                curl_easy_setopt(handle, CURLOPT_USERPWD, in);
            }

            // timeout values
            curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 15);
            curl_easy_setopt(handle, CURLOPT_TIMEOUT, 15);

            curl_easy_setopt(handle, CURLOPT_USERAGENT, "Bergamota Wifi/1.0");
            curl_easy_setopt(handle, CURLOPT_WRITEDATA, devnull);

            res = curl_easy_perform(handle);
            fclose(devnull);

            if(res!=CURLE_OK)
            {
                DEBUG("ERROR failed to update: %s", curl_easy_strerror(res));
            }

            curl_easy_cleanup(handle);

            free(buf);
        }
    }

    config_close();

    return(EXIT_SUCCESS);
}