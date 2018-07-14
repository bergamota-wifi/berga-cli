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
#include <signal.h>
#include <setjmp.h>
#include <signal.h>

#include "main.h"
#include "utils.h"
#include "ddns.h"

jmp_buf rpoint;

void sig_handler(int sig)
{
    if(sig == SIGSEGV)
    {
        printf("Received segfault\n");
        signal(SIGSEGV, &sig_handler);
        longjmp(rpoint, SIGSEGV);
    }
}

int main(int argc, char **argv)
{
    signal(SIGSEGV, &sig_handler);

    int fcode = setjmp(rpoint);

    if(fcode == 0)
    {
        char *fname;

        fname = basename(argv[0]);

        if(argc>=1)
        {
            // pppd ip-up/ip-down
            if(IS(fname, "ip-up") || IS(fname, "ip-down") || IS(fname, "ipv6-up") || IS(fname, "ipv6-down"))
            {
                DEBUG("pppd script mode called");

                pppd_script_command(argc, argv);
                return EXIT_SUCCESS;
            }
            // udhcpc lease
            else if(IS(fname, "udhcpc-script"))
            {
                DEBUG("udhcpc script mode called");

                udhcpc_lease_command(argv[1]);
                return EXIT_SUCCESS;
            }

            if(argc>=2)
            {
                if(IS(fname, "berga-cli"))
                {
                    // system startup
                    if(IS(argv[1], "sysinit"))
                    {
                        DEBUG("sysinit script mode called");

                        print_log("INIT: System startup requested\n");
                        sysinit_main(argc, argv);
                    }
                    else
                    if(IS(argv[1], "get"))
                    {
                        if(argc>=3)
                        {
                            config_open();

                            char *value = config_read_string(argv[2]);

                            printf("%s\n", is_empty(value)?"<empty>":value);

                            config_close();
                        }
                    }
                    else
                    if(IS(argv[1], "set"))
                    {
                        if(argc>=4)
                        {
                            config_open();

                            config_write_string(argv[2], argv[3]);

                            config_save(false);
                            config_close();
                        }
                    }
                    else
                    if(IS(argv[1], "ddnsupdate"))
                    {
                        ddns_main(argc, argv);
                    }
                    else
                    if(IS(argv[1], "factorydefaults"))
                    {
                        factorydefaults();
                    }
                    else
                    if(IS(argv[1], "cpuload"))
                    {
                        cpuload();
                    }
                    else
                    if(IS(argv[1], "save"))
                    {
                        config_open();
                        config_save(true);
                        config_close();
                    }

                    return EXIT_SUCCESS;
                }
            }
        }
    }
    else
    {
        DEBUG("Application crashed, received a SIGSEGV code: %d", fcode);
        exit(EXIT_FAILURE);
    }

    return EXIT_FAILURE;
}