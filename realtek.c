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
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <netinet/ether.h>

#include "realtek.h"
#include "utils.h"
#include "sha1.h"

bool read_hw_settings(struct hw_header *hw)
{
    memset(hw, 0, sizeof(struct hw_header));

    if(hwflash_read(hw, sizeof(struct hw_header)))
    {
        // from realtek SDK, HW default settings header
        if(hw->signature[0]!='H' && hw->signature[1]!='6')
        {
            DEBUG("WARN: blank signature header found");

            hw->signature[0] = 0x48; //H
            hw->signature[1] = 0x36; //6
            hw->signature[2] = 0x30;
            hw->signature[3] = 0x31;
            hw->len = 0x048E;
            hw->boardVer = 0x2;

            if(hw->nic[0].ether_addr_octet[0]==0 && 
               hw->nic[0].ether_addr_octet[1]==0 &&
               hw->nic[0].ether_addr_octet[3]==0)
            {
                DEBUG("Blank MAC address found, setting defaults");

                //78:44:76:81:96:c1
                for(int i=0; i<MAX_HWADDR; i++)
                {
                    hw->nic[i].ether_addr_octet[0] = 0x78;
                    hw->nic[i].ether_addr_octet[1] = 0x44;
                    hw->nic[i].ether_addr_octet[2] = 0x76;
                    if(i<8)
                    {
                        hw->nic[i].ether_addr_octet[3] = 0x81;
                        hw->nic[i].ether_addr_octet[4] = 0x96;
                        hw->nic[i].ether_addr_octet[5] = 0xC1+i;
                    }
                }
            }
        }

        DEBUG("Reading default HW settings, board ver: %d, len: %d", hw->boardVer, hw->len);

        for(int i=0; i<MAX_HWADDR; i++)
            DEBUG("MAC%d: %s", i, ether_ntoa_z(&hw->nic[i]));

        for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
            DEBUG("pwrlevelCCK_A: 0x%02x", hw->pwrlevelCCK_A[i]);

        for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
            DEBUG("pwrlevelCCK_B: 0x%02x", hw->pwrlevelCCK_B[i]);

        for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
            DEBUG("pwrlevelHT40_1S_A: 0x%02x", hw->pwrlevelHT40_1S_A[i]);

        for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
            DEBUG("pwrlevelHT40_1S_B: 0x%02x", hw->pwrlevelHT40_1S_B[i]);

        for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
            DEBUG("pwrdiffHT40_2S: 0x%02x", hw->pwrdiffHT40_2S[i]);

        for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
            DEBUG("pwrdiffHT20: 0x%02x", hw->pwrdiffHT20[i]);

        for(int i=0; i<MAX_2G_CHANNEL_NUM_MIB; i++)
            DEBUG("pwrdiffOFDM: 0x%02x", hw->pwrdiffOFDM[i]);

        DEBUG("regDomain: 0x%02x", hw->regDomain);
        DEBUG("rfType: 0x%02x", hw->rfType);
        DEBUG("ledType: 0x%02x", hw->ledType);
        DEBUG("xCap: 0x%02x", hw->xCap);
        DEBUG("TSSI1: 0x%02x", hw->TSSI1);
        DEBUG("TSSI2: 0x%02x", hw->TSSI2);
        DEBUG("Ther: 0x%02x", hw->Ther);

        return true;
    }
    else
        DEBUG("ERROR: failed to read from flash device ?");

    return false;
}

bool hwflash_read(struct hw_header *hw, int len)
{
    FILE *f;
    int ok = true;

    f = fopen(HWINFO_DEVICE_NAME, "rb");

    if(!f)
        return false;

    if(fread(hw, 1, len, f) != len)
    {
        DEBUG("Wrong read length, alignment issue?");
        ok = false;
    }

    fclose(f);

    return ok;
}

bool upgrade_fwimage(unsigned char *data)
{
    struct img_header header;
    size_t offs = 0;
    FILE *f;

    f = fopen("/dev/mtdblock0", "wb");
    if(!f)
        return false;

    // copy header
    memset(&header, 0, sizeof(struct img_header));
    memcpy(&header, data+offs, sizeof(struct img_header));

    // check if boot code update is present
    if(*(unsigned int *)header.signature == 0x626f6f74)
    {
        printf("Boot code header update, len: %d bytes\n", header.len);

        fseek(f, 0, SEEK_SET);
        fwrite(data+sizeof(struct img_header), 1, header.len, f);   // skip header

        offs += header.len+sizeof(struct img_header);
    }


    // copy kernel header
    memset(&header, 0, sizeof(struct img_header));
    memcpy(&header, data+offs, sizeof(struct img_header));

    // cr6c header with root (kernel first)
    if(*(unsigned int *)header.signature == 0x63723663)
    {
        printf("Kernel code header update, len: %d bytes\n", header.len);

        fseek(f, FW_KERNEL_OFFSET, SEEK_SET);
        fwrite(data+offs, 1, header.len+sizeof(struct img_header), f);

        offs += header.len+sizeof(struct img_header);
    }
    else
    {
        fclose(f);
        return false;
    }

    // copy rootfs header
    memset(&header, 0, sizeof(struct img_header));
    memcpy(&header, data+offs, sizeof(struct img_header));

    // r6cr root file header
    if(*(unsigned int *)header.signature == 0x72366372)
    {
        printf("Rootfs code header update, len: %d bytes\n", header.len);

        fseek(f, FW_ROOTFS_OFFSET, SEEK_SET);
        fwrite(data+offs+sizeof(struct img_header), 1, header.len, f);  // skip header
    }
    else
    {
        fclose(f);
        return false;
    }

    DEBUG("Firmware upgrade finished");

    fflush(f);
    fclose(f);

    return true;
}

void check_mtdconfig()
{
    struct hw_header hw;
    char *hash;

    sysexec(true, "mount", "-t jffs2 /dev/mtdblock2 /mnt");

    // setup initial configuration file at first startup
    if(!file_exists("/mnt/berga-cli.json"))
    {
        printf("INIT: First startup, setting up JFFS2 flash device\n");

        // try umount device first
        sysexec(true, "umount", "/mnt");

        // format jffs2 flash device
        sysexec(true, "flash_eraseall", "-j /dev/mtd2");

        config_adapt();
        config_save(true);

        DEBUG("MTD device setup complete");
    }
    else
    {
        // copy present configuration from flash
        sysexec(true, "cp", "/mnt/berga-cli.json /etc/berga-cli.json");

        config_open();
        config_adapt();

        sysexec(true, "umount", "/mnt");
    }

    if(read_hw_settings(&hw))
    {
        char *mac, *macdefault;

        mac = config_read_string("network.wan.macaddr");
        macdefault = config_read_string("network.wan.macdefault");

        // write mac address from flash device
        config_write_string("network.lan.macaddr", ether_ntoa_z(&hw.nic[0]));
        config_write_string("network.primary_wireless.macaddr", ether_ntoa_z(&hw.nic[2]));
        config_write_string("network.secondary_wireless.macaddr", ether_ntoa_z(&hw.nic[3]));
        config_write_string("network.third_wireless.macaddr", ether_ntoa_z(&hw.nic[4]));

        // check for custom mac address on WAN
        if(IS(mac, macdefault))
        {
            // mac not changed, copy wan mac
            config_write_string("network.wan.macaddr", ether_ntoa_z(&hw.nic[1]));
            config_write_string("network.wan.macdefault", ether_ntoa_z(&hw.nic[1]));
        }
        else
        {
            // mac changed, copy only default
            config_write_string("network.wan.macdefault", ether_ntoa_z(&hw.nic[1]));
        }
    }

    config_save(false);
    config_close();
}