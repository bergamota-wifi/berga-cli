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

#include <stdbool.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <net/ethernet.h>

#ifndef REALTEK_H
#define	REALTEK_H

#ifdef	__cplusplus
extern "C" {
#endif

#define HWINFO_DEVICE_NAME		"/dev/mtdblock1"

#define HW_SETTING_OFFSET		0x6000
#define HW_SETTING_SECTOR_LEN   (0x8000-0x6000)
#define FW_KERNEL_OFFSET        0x10000
#define FW_ROOTFS_OFFSET        0x150000

// Hardware setting MIB
#define MIB_HW_BOARD_VER		200
#define MIB_HW_NIC0_ADDR		201
#define MIB_HW_NIC1_ADDR		202
#define MIB_HW_WLAN_ADDR		203
#define MIB_HW_REG_DOMAIN		204
#define MIB_HW_RF_TYPE			205
#define MIB_HW_TX_POWER_CCK		206
#define MIB_HW_TX_POWER_OFDM    207
#define MIB_HW_ANT_DIVERSITY    208
#define MIB_HW_TX_ANT			209
#define MIB_HW_CCA_MODE			210
#define MIB_HW_PHY_TYPE			211
#define MIB_HW_LED_TYPE			212
#define MIB_HW_INIT_GAIN		213

#define TAG_LEN				2
#define SIGNATURE_LEN			4

#define HW_SETTING_VER			2	// hw setting version (2441)

#define MAX_HWADDR                      10

#define MAX_2G_CHANNEL_NUM_MIB		14
#define MAX_CCK_CHAN_NUM                14
#define MAX_OFDM_CHAN_NUM               162

// firmware file header
struct img_header
{
    unsigned char signature[SIGNATURE_LEN];
    unsigned int startAddr;
    unsigned int burnAddr;
    unsigned int len;
};

/* Config file header */
struct hw_header
{
    unsigned char signature[SIGNATURE_LEN];
    unsigned short len;
    unsigned char boardVer;

    struct ether_addr nic[MAX_HWADDR];

    unsigned char pwrlevelCCK_A[MAX_2G_CHANNEL_NUM_MIB]; // CCK Tx power for each channel
    unsigned char pwrlevelCCK_B[MAX_2G_CHANNEL_NUM_MIB]; // CCK Tx power for each channel
    unsigned char pwrlevelHT40_1S_A[MAX_2G_CHANNEL_NUM_MIB]; 
    unsigned char pwrlevelHT40_1S_B[MAX_2G_CHANNEL_NUM_MIB]; 
    unsigned char pwrdiffHT40_2S[MAX_2G_CHANNEL_NUM_MIB];
    unsigned char pwrdiffHT20[MAX_2G_CHANNEL_NUM_MIB];
    unsigned char pwrdiffOFDM[MAX_2G_CHANNEL_NUM_MIB];
    unsigned char regDomain; // regulation domain
    unsigned char rfType; // RF module type
    unsigned char ledType; // LED type, see LED_TYPE_T for definition
    unsigned char xCap; 
    unsigned char TSSI1; 
    unsigned char TSSI2; 
    unsigned char Ther; 
}  __attribute__ ((packed));


bool read_hw_settings(struct hw_header *hw);
bool hwflash_read(struct hw_header *hw, int len);
bool hwflash_write(struct hw_header *hw, int len);

bool upgrade_fwimage(unsigned char *data);

void check_mtdconfig();

#ifdef	__cplusplus
}
#endif

#endif	/* REALTEK_H */

