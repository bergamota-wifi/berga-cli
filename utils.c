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
#include <stdarg.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>

#include "cjson.h"
#include "utils.h"
#include "main.h"
#include "sha1.h"
#include "realtek.h"

static char *json_cfg = NULL;
cJSON *json_root = NULL;

char *get_wan_ipv4()
{
    int fd;
    struct ifreq ifr;
    const char *dev = wan_devname();

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IF_NAMESIZE-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

in_addr_t a_to_hl(char *ipstr)
{
    struct in_addr in;

    if(!inet_aton(ipstr, &in))
    {
        DEBUG("Could not convert string to netshort!");
        exit(0);
    }

    return(ntohl(in.s_addr));
}

bool addr_in_range(char *addr, char *net, char *mask)
{
    in_addr_t ip = a_to_hl(addr);
    in_addr_t netip = a_to_hl(net);
    in_addr_t netmask = a_to_hl(mask);

    in_addr_t netstart = (netip & netmask);
    in_addr_t netend = (netstart | ~netmask);

    if((ip >= netstart) && (ip <= netend))
        return true;

    return false;
}

// lookup associated IP address to MAC address (NOT thread safe))
char *mac2ipaddr(char *macaddr)
{
    static char hostip[32];
    char ip[32], arp[32], iface[32];
    FILE *stream;
    char *line = NULL;
    size_t len = 0;

    strcpy(hostip, "0.0.0.0");

    stream = fopen("/proc/net/arp", "r");
    if (stream == NULL)
        return hostip;

    while(getline(&line, &len, stream) != -1)
    {
        sscanf(line,"%s\t%*s\t%*s\t%s\t%*s\t%s", ip, arp, iface);

        if(IS(macaddr, arp))
        {
            strlcpy(hostip, ip, sizeof(hostip));
            break;
        }
    }

    free(line);
    fclose(stream);

    return hostip;
}

// return pointer to static buffer
char *hash_password(char *pass)
{
    SHA1_CTX ctx;
    unsigned char hash[20];
    static char buf[41];

    SHA1Init(&ctx);
    SHA1Update(&ctx, (unsigned char *)pass, strlen(pass));
    SHA1Final(hash, &ctx);

    for(int i = 0; i < 20; i++)
        sprintf(buf + i * 2, "%02x", hash[i]);
    buf[40] = '\0';

    return buf;
}

// return pointer to static buffer
char *random_seed()
{
    unsigned long seed[2];
    static char salt[] = "........";
    const char *const seedchars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    int i;

    FILE *f = fopen("/dev/urandom", "r");
    fread(&seed[0], sizeof(unsigned long), 1, f);
    fclose(f);

    //seed[0] = time(NULL);
    seed[1] = seed[0] >> 14 & 0x30000;

    for (i = 0; i < 8; i++)
      salt[i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];

    return salt;
}

// convert and print data size on a pre-allocated buffer
char *byte_units(unsigned long bytes)
{
    const char *units[] = { "B","KB","MB","GB","TB","PB","EB","ZB","YB" };
    char *buf;
    int count = 0;

    while(bytes>=1024)
    {
        count++;
        bytes/=1024;
    }

    asprintf(&buf, "%lu %s", bytes, units[count]);

    return buf;
}

char *wifi_bandtable24(int reg)
{
    static struct
    {
        int reg;
        int chan;
        char region[24];
    } band[] = { {0, 0,  ""},
                 {1, 11, "FCC"},
                 {2, 11, "IC"},
                 {3, 13, "ETSI"},
                 {4, 13, "SPAIN"},
                 {5, 4, "FRANCE"},
                 {6, 14, "MKK"},
                 {7, 11, "ISRAEL"},
                 {8, 14, "MKK1"},
                 {9, 14, "MKK2"},
                 {10,14, "MKK3"},
                 {11,11, "NCC"},
                 {12,13, "RUSSIAN"},
                 {13,13, "CN "},
                 {14,14, "Global"},
                 {15,13, "World_wide"},
                 {16,14, "Test"} };

    return band[reg].region;
}

int mw2dbm(float mw)
{
    return floor(10.0 * log10(mw / 1.0));
}

float dbm2mw(int dbm)
{
    return powf(10.0, dbm / 10.0);
}

bool valid_ipv4(const char *ipaddr)
{
    unsigned char buf[sizeof(struct in_addr)];

    int result = inet_pton(AF_INET, ipaddr, buf);
    return result != 0;
}

bool valid_ipv6(const char *ipaddr)
{
    unsigned char buf[sizeof(struct in6_addr)];

    int result = inet_pton(AF_INET6, ipaddr, buf);
    return result != 0;
}

bool valid_mac(const char *macaddr)
{
    struct ether_addr *ea;
    ea = ether_aton(macaddr);

    return ea != NULL;
}

// returns true if string does not have spaces
bool no_spaces(char *str)
{
    for(int i = 0; str[i] != '\0'; ++i)
    {
        if(isspace(str[i]))
            return false;
    }

    return true;
}

// returns true if string has only numbers
bool only_numbers(char *str)
{
    for(int i = 0; str[i] != '\0'; ++i)
    {
        if(!(isdigit(str[i])))
            return false;
    }

    return true;
}

// returns true if string has only letters
bool only_letters(char *str)
{
    for(int i = 0; str[i] != '\0'; ++i)
    {
        if(!(isalpha(str[i])))
            return false;
    }

    return true;
}

// returns true if string has only letters or numbers
bool only_alphanumeric(char *str)
{
    for(int i = 0; str[i] != '\0'; ++i)
    {
        if(!(isalpha(str[i])) && !(isdigit(str[i])))
            return false;
    }

    return true;
}

bool no_specialchars(char *str)
{
    for(int i = 0; str[i] != '\0'; ++i)
    {
        if(!(isprint(str[i])))
            return false;
    }

    return true;
}

void replace_spaces(char *filename)
{
    if(filename == NULL)
        return;

    rtrim(filename);
    for(int i = 0; i < strlen(filename); ++i)
    {
        if(*(filename + i) == ' ')
            *(filename + i) = '-';
    }
}

bool is_empty(char *str)
{
    if(!str)
        return true;

    if(strlen(str)<=0)
        return true;

    // test for consecutive blanks
    for(int i = 0; str[i] != '\0'; ++i)
    {
        if(!isblank(str[i]))
            return false;
    }

    return true;
}

int directory_exists(const char *path)
{
    DIR *dir = NULL;
    int success;

    replace_spaces((char *)path);
    dir = opendir(path);
    if(dir)
    {
        closedir(dir);
        success = 1;
    }
    else if(ENOENT == errno)
        success = 0; // The directory doesn't exist
    else
        success = -1; // Something went wrong with opening it

    return success;
}

int directory_create(const char *path)
{
    replace_spaces((char *)path);
    return mkdir(path, 0755);
}

void reboot()
{
    FILE *f = fopen("/proc/sysrq-trigger", "w");

    sync();
    fputs("b\n", f);
    fclose(f);

    for(;;);
}

void factorydefaults()
{
    // format jffs2 flash device
    sysexec(true, "flash_eraseall", "-j /dev/mtd2");

    reboot();
}

char *json_getvalue_string(cJSON *j, int pos, char *value)
{
    cJSON *item = cJSON_GetArrayItem(j, pos);
    cJSON *val = cJSON_GetObjectItem(item, value);

    if(item && val)
        return val->valuestring;
    else
        return "";
}

//! read a json file into a dynamic allocated buffer
size_t read_file(char **data, const char *filename)
{
    size_t len;
    FILE *f;

    f = fopen(filename, "rb");

    if(!f)
    {
        DEBUG("Tried to read an inexistent file [%s]!", filename);
        return 0;
    }

    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    *data = (char *)malloc(len + 1);

    if(!*data)
    {
        perror("read_file malloc failed!");
        exit(EXIT_FAILURE);
    }

    fread(*data, 1, len, f);
    fclose(f);

    return len;
}

void config_open()
{
    if(read_file(&json_cfg, "/etc/berga-cli.json"))
    {
        json_root = cJSON_Parse(json_cfg);

        if(!json_root)
        {
            DEBUG("JSON ERROR: Error parsing configuration file: %s", cJSON_GetErrorPtr());
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        perror("Could not read main JSON file! Unrecoverable exception!");
        exit(0);
    }
}

void config_close()
{
    // free used memory
    if(json_root)
        cJSON_Delete(json_root);
    if(json_cfg)
        free(json_cfg);
}

// save configuration file, if commit is true, copy it to flash device
void config_save(bool commit)
{
    char *out;
    FILE *f;

    f = fopen("/etc/berga-cli.json", "w");
    out = cJSON_Print(json_root);

    fputs(out, f);
    fclose(f);

    free(out);

    if(commit)
    {
        sysexec(true, "mount", "-t jffs2 /dev/mtdblock2 /mnt");
        sysexec(true, "cp", "/etc/berga-cli.json /mnt/berga-cli.json");
        sysexec(true, "umount", "/mnt");

        DEBUG("Configuration file commited to flash device.");
    }
}

cJSON *config_get_node(const char *cfgpath)
{
    char *token, *buf;
    cJSON *next;

    if(!json_root)
    {
        DEBUG("Tried to config_get_node without calling config_open first!");
        return NULL;
    }

    // copy buffer on stack and parse root node first
    buf = strdup(cfgpath);
    token = strsep(&buf, ".");
    next = cJSON_GetObjectItem(json_root, token);

    // only proceed if a root node is present
    if(next)
    {
        // iterate over config fields
        while(buf != NULL)
        {
            token = strsep(&buf, ".");
            next = cJSON_GetObjectItem(next, token);

            if(!next)
            {
                DEBUG("Invalid configuration file object path [%s] (not found)\n", cfgpath);
                return NULL;
            }
        }
    }
    else
    {
        DEBUG("Invalid config root node! [%s]\n", token);
        return NULL;
    }

    free(buf);

    return next;
}

cJSON *config_get_node_id(const char *cfgpath, int which, char *name)
{
    cJSON *next = config_get_node(cfgpath);

    if(next)
    {
        cJSON *item = cJSON_GetArrayItem(next, which);

        if(item)
        {
            cJSON *value = cJSON_GetObjectItem(item, name);

            if(value)
                return value;
        }
    }

    DEBUG("Invalid object ID requested! [%s]:%d", cfgpath, which);

    return NULL;
}

bool config_delete_item(const char *cfgpath, int which)
{
    cJSON *next = config_get_node(cfgpath);

    if(next)
        cJSON_DeleteItemFromArray(next, which);
    else
        return false;

    return true;
}

// delete all items inside json array
bool config_delete_array(const char *arraypath)
{
    cJSON *next = config_get_node(arraypath);

    if(next)
    {
        for(int x=cJSON_GetArraySize(next); x>=0; x--)
        {
            cJSON_DeleteItemFromArray(next, x);
            DEBUG("Delete item %d", x);
        }
    }
    else
        return false;

    return true;
}

// concatenate json array
bool config_insert_item(const char *cfgpath, cJSON *item)
{
    cJSON *next = config_get_node(cfgpath);

    if(next)
        cJSON_AddItemToArray(next, item);
    else
        return false;

    return true;
}

bool config_replace_item(const char *cfgpath, int which, cJSON *item)
{
    cJSON *next = config_get_node(cfgpath);

    if(next)
        cJSON_ReplaceItemInArray(next, which, item);
    else
        return false;

    return true;
}

char *config_read_string(char *cfgpath)
{
    cJSON *next = config_get_node(cfgpath);

    if(next)
    {
        if(next->type == cJSON_String)
            return next->valuestring;
        else
            return "";
    }
    else
        return "";
}

//! returns boolean true if field content is "true"
bool config_item_active(char *cfgpath)
{
    cJSON *next = config_get_node(cfgpath);

    if(next)
    {
        if(next->type == cJSON_String)
        {
            if(IS(next->valuestring, "true"))
                return true;
        }
    }

    return false;
}

void config_write_string(char *cfgpath, char *value)
{
    cJSON *next = config_get_node(cfgpath);

    DEBUG("CFG WRITE DUMP: %s -> %s", cfgpath, value);

    if(next)
    {
        // TODO: Assume value is already allocated by cjson (present on berga-cli.json)
        if(next->type == cJSON_String)
        {
            free(next->valuestring);
            next->valuestring = strdup(value);
        }
        else
            DEBUG("Tried to write to an invalid json field, [%s]: %s", cfgpath, value);
    }
}

void config_write_integer(char *cfgpath, int value)
{
    char *tmp;

    asprintf(&tmp, "%i", value);
    config_write_string(cfgpath, tmp);

    free(tmp);
}

void config_adapt()
{
    cJSON *sub1, *sub2, *sub3;

    if(!json_root)
        json_root = cJSON_CreateObject();

    struct jsdata_t jsdata[] =
    {
        { cJSON_Object, &json_root, &sub1, "system", NULL },
            { cJSON_String, &sub1, NULL, "hostname", "bergamota-ng" },
            { cJSON_String, &sub1, NULL, "username", "admin" },
            { cJSON_String, &sub1, NULL, "password", "d033e22ae348aeb5660fc2140aec35850c4da997" },
            { cJSON_String, &sub1, NULL, "timezone", "BRT3" },
            { cJSON_String, &sub1, NULL, "timezonedst", "false" },

            { cJSON_Object, &sub1, &sub2, "timeservers", NULL },
                { cJSON_String, &sub2, NULL, "server1", "0.pool.ntp.org" },
                { cJSON_String, &sub2, NULL, "server2", "1.pool.ntp.org" },
                { cJSON_String, &sub2, NULL, "server3", "2.pool.ntp.org" },
                { cJSON_String, &sub2, NULL, "server4", "3.pool.ntp.org" },

            { cJSON_Object, &sub1, &sub2, "watchdog", NULL },
                { cJSON_String, &sub2, NULL, "active", "false" },
                { cJSON_String, &sub2, NULL, "timeout", "5" },
                { cJSON_String, &sub2, NULL, "ipaddr", "" },

        { cJSON_Object, &json_root, &sub1, "firewall", NULL },
            { cJSON_Object, &sub1, &sub2, "basic", NULL },
            { cJSON_String, &sub2, NULL, "wanaccess", "false" },
            { cJSON_String, &sub2, NULL, "wanddos", "true" },
            { cJSON_String, &sub2, NULL, "wanping", "false" },
            { cJSON_String, &sub2, NULL, "wanupnp", "false" },

            { cJSON_Object, &sub1, &sub2, "advanced", NULL },
            { cJSON_String, &sub2, NULL, "default_rule", "true" },
            { cJSON_Array, &sub2, &sub3, "rules", NULL },

            { cJSON_Object, &sub1, &sub2, "maccontrol", NULL },
            { cJSON_String, &sub2, NULL, "default_rule", "true" },
            { cJSON_Array, &sub2, &sub3, "rules", NULL },

            { cJSON_Object, &sub1, &sub2, "dmz", NULL },
            { cJSON_String, &sub2, NULL, "active", "false" },
            { cJSON_String, &sub2, NULL, "ipaddr", "" },

        { cJSON_Object, &json_root, &sub1, "portforward", NULL },
            { cJSON_Array, &sub1, &sub2, "redirects", NULL },

        { cJSON_Object, &json_root, &sub1, "network", NULL },
            { cJSON_Object, &sub1, &sub2, "wireless", NULL },
            { cJSON_String, &sub2, NULL, "active", "true" },
            { cJSON_String, &sub2, NULL, "hidden", "false" },
            { cJSON_String, &sub2, NULL, "opmode", "master" },
            { cJSON_String, &sub2, NULL, "mode", "n" },
            { cJSON_String, &sub2, NULL, "channel", "1" },
            { cJSON_String, &sub2, NULL, "encryption", "wpa2-aes" },
            { cJSON_String, &sub2, NULL, "isolation", "false" },
            { cJSON_String, &sub2, NULL, "txpower", "0" },
            { cJSON_String, &sub2, NULL, "txrate", "max" },
            { cJSON_String, &sub2, NULL, "threshold", "false" },
            { cJSON_String, &sub2, NULL, "min_signal", "15" },

            { cJSON_Object, &sub1, &sub2, "primary_wireless", NULL },
            { cJSON_String, &sub2, NULL, "active", "true" },
            { cJSON_String, &sub2, NULL, "hidden", "false" },
            { cJSON_String, &sub2, NULL, "timecontrol", "false" },
            { cJSON_String, &sub2, NULL, "ssid", "Bergamota-NG" },
            { cJSON_String, &sub2, NULL, "password", "" },
            { cJSON_String, &sub2, NULL, "macaddr", "" },

            { cJSON_Object, &sub1, &sub2, "secondary_wireless", NULL },
            { cJSON_String, &sub2, NULL, "active", "false" },
            { cJSON_String, &sub2, NULL, "hidden", "false" },
            { cJSON_String, &sub2, NULL, "timecontrol", "false" },
            { cJSON_String, &sub2, NULL, "ssid", "Bergamota-NG 2" },
            { cJSON_String, &sub2, NULL, "password", "" },
            { cJSON_String, &sub2, NULL, "ipaddr", "172.16.5.1" },
            { cJSON_String, &sub2, NULL, "netmask", "255.255.255.0" },
            { cJSON_String, &sub2, NULL, "macaddr", "" },

            { cJSON_Object, &sub1, &sub2, "third_wireless", NULL },
            { cJSON_String, &sub2, NULL, "active", "false" },
            { cJSON_String, &sub2, NULL, "hidden", "false" },
            { cJSON_String, &sub2, NULL, "protected", "false" },
            { cJSON_String, &sub2, NULL, "timecontrol", "false" },
            { cJSON_String, &sub2, NULL, "ssid", "Bergamota-NG 3" },
            { cJSON_String, &sub2, NULL, "password", "" },
            { cJSON_String, &sub2, NULL, "ipaddr", "172.16.10.1" },
            { cJSON_String, &sub2, NULL, "netmask", "255.255.255.0" },
            { cJSON_String, &sub2, NULL, "macaddr", "" },

            { cJSON_Object, &sub1, &sub2, "repeater_wireless", NULL },
            { cJSON_String, &sub2, NULL, "ssid", "" },
            { cJSON_String, &sub2, NULL, "password", "" },
            { cJSON_String, &sub2, NULL, "channel", "1" },
            { cJSON_String, &sub2, NULL, "encryption", "wpa2-aes" },

            { cJSON_Object, &sub1, &sub2, "lan", NULL },
            { cJSON_String, &sub2, NULL, "mode", "single" },
            { cJSON_String, &sub2, NULL, "ipaddr", "172.16.1.1" },
            { cJSON_String, &sub2, NULL, "netmask", "255.255.255.0" },
            { cJSON_String, &sub2, NULL, "macaddr", "" },

            { cJSON_Object, &sub1, &sub2, "wan", NULL },
            { cJSON_String, &sub2, NULL, "opmode", "gateway" },
            { cJSON_String, &sub2, NULL, "mode", "dhcp" },
            { cJSON_String, &sub2, NULL, "hostname", "" },
            { cJSON_String, &sub2, NULL, "pppoe_username", "" },
            { cJSON_String, &sub2, NULL, "pppoe_password", "" },
            { cJSON_String, &sub2, NULL, "pppoe_acname", "" },
            { cJSON_String, &sub2, NULL, "pppoe_svname", "" },
            { cJSON_String, &sub2, NULL, "ipaddr", "" },
            { cJSON_String, &sub2, NULL, "netmask", "" },
            { cJSON_String, &sub2, NULL, "gateway", "" },
            { cJSON_String, &sub2, NULL, "macaddr", "" },
            { cJSON_String, &sub2, NULL, "macdefault", "" },
            { cJSON_String, &sub2, NULL, "mtu", "1500" },
            { cJSON_String, &sub2, NULL, "disable_nat", "false" },

            { cJSON_Object, &sub1, &sub2, "wangsm", NULL },
            { cJSON_String, &sub2, NULL, "active", "false" },
            { cJSON_String, &sub2, NULL, "apn", "" },
            { cJSON_String, &sub2, NULL, "network", "" },
            { cJSON_String, &sub2, NULL, "username", "" },
            { cJSON_String, &sub2, NULL, "password", "" },

            { cJSON_Object, &sub1, &sub2, "dns", NULL },
            { cJSON_String, &sub2, NULL, "active", "false" },
            { cJSON_String, &sub2, NULL, "dns1", "" },
            { cJSON_String, &sub2, NULL, "dns2", "" },
            { cJSON_String, &sub2, NULL, "dns3", "" },

            { cJSON_Object, &sub1, &sub2, "qos", NULL },
            { cJSON_String, &sub2, NULL, "active", "false" },
            { cJSON_String, &sub2, NULL, "primary_upload", "" },
            { cJSON_String, &sub2, NULL, "primary_download", "" },
            { cJSON_String, &sub2, NULL, "secondary_upload", "" },
            { cJSON_String, &sub2, NULL, "secondary_download", "" },
            { cJSON_String, &sub2, NULL, "third_upload", "" },
            { cJSON_String, &sub2, NULL, "third_download", "" },

            { cJSON_Object, &sub1, &sub2, "dhcp", NULL },
            { cJSON_String, &sub2, NULL, "active", "true" },
            { cJSON_String, &sub2, NULL, "start", "172.16.1.2" },
            { cJSON_String, &sub2, NULL, "end", "172.16.1.254" },
            { cJSON_String, &sub2, NULL, "secondary_start", "172.16.5.2" },
            { cJSON_String, &sub2, NULL, "secondary_end", "172.16.5.254" },
            { cJSON_String, &sub2, NULL, "third_start", "172.16.10.2" },
            { cJSON_String, &sub2, NULL, "third_end", "172.16.10.254" },
            { cJSON_String, &sub2, NULL, "leasetime", "1" },
            { cJSON_Array, &sub2, &sub3, "leases", NULL },

            { cJSON_Object, &sub1, &sub2, "ipv6", NULL },
            { cJSON_String, &sub2, NULL, "active", "false" },
            { cJSON_String, &sub2, NULL, "wan_mode", "dhcp" },
            { cJSON_String, &sub2, NULL, "lan_mode", "radv" },
            { cJSON_String, &sub2, NULL, "wan_prefix", "64" },
            { cJSON_String, &sub2, NULL, "wan_addr", "" },
            { cJSON_String, &sub2, NULL, "wan_gateway", "" },
            { cJSON_String, &sub2, NULL, "wan_mtu", "1500" },
            { cJSON_String, &sub2, NULL, "lan_prefix", "64" },
            { cJSON_String, &sub2, NULL, "lan_addr", "" },
            { cJSON_String, &sub2, NULL, "dhcp_start", "1000" },
            { cJSON_String, &sub2, NULL, "dhcp_end", "2000" },
            { cJSON_String, &sub2, NULL, "pppoe_username", "" },
            { cJSON_String, &sub2, NULL, "pppoe_password", "" },
            { cJSON_String, &sub2, NULL, "dhcp_lease", "1" },
            { cJSON_String, &sub2, NULL, "dnsactive", "false" },
            { cJSON_String, &sub2, NULL, "dns1", "" },
            { cJSON_String, &sub2, NULL, "dns2", "" },
            { cJSON_String, &sub2, NULL, "dns3", "" },

        { cJSON_Object, &json_root, &sub1, "ddns", NULL },
            { cJSON_String, &sub1, NULL, "active", "false" },
            { cJSON_String, &sub1, NULL, "service", "" },
            { cJSON_String, &sub1, NULL, "username", "" },
            { cJSON_String, &sub1, NULL, "password", "" },
            { cJSON_String, &sub1, NULL, "domain", "" },

        { cJSON_Object, &json_root, &sub1, "remoteshell", NULL },
            { cJSON_String, &sub1, NULL, "active", "true" },
            { cJSON_String, &sub1, NULL, "username", "" },
            { cJSON_String, &sub1, NULL, "password", "" },
            { cJSON_String, &sub1, NULL, "key_rsa", "" },
            { cJSON_String, &sub1, NULL, "key_dss", "" },
            { cJSON_String, &sub1, NULL, "key_ecdsa", "" },
            { cJSON_String, &sub1, NULL, "network", "lan" },

        { cJSON_Object, &json_root, &sub1, "timecontrol", NULL },
            { cJSON_Object, &sub1, &sub2, "primary_wireless", NULL },
            { cJSON_String, &sub2, NULL, "blacklist", "true" },
            { cJSON_Array, &sub2, &sub3, "rules", NULL },

            { cJSON_Object, &sub1, &sub2, "secondary_wireless", NULL },
            { cJSON_String, &sub2, NULL, "blacklist", "true" },
            { cJSON_Array, &sub2, &sub3, "rules", NULL },

            { cJSON_Object, &sub1, &sub2, "third_wireless", NULL },
            { cJSON_String, &sub2, NULL, "blacklist", "true" },
            { cJSON_Array, &sub2, &sub3, "rules", NULL },
            { 0, NULL, NULL, NULL, NULL }
    };

    struct jsdata_t *p = jsdata;

    while(p->datatype)
    {
        if(p->datatype == cJSON_Object)
        {
            cJSON *t = cJSON_GetObjectItem(*p->root, p->fieldname);
            if(t)
            {
                DEBUG("Object exists! %s", p->fieldname);
                *p->child = t;
            }
            else
            {
                DEBUG("Add object: %s", p->fieldname);
                cJSON_AddItemToObject(*p->root, p->fieldname, *p->child = cJSON_CreateObject());
            }
        }
        else
        if(p->datatype == cJSON_Array)
        {
            cJSON *t = cJSON_GetObjectItem(*p->root, p->fieldname);
            if(t)
            {
//                printf("%s", cJSON_Print(t));

//                printf("Array exists! %s\n", p->fieldname);
//                *p->child = *p->root;
            }
            else
            {
                cJSON_AddItemToObject(*p->root, p->fieldname, *p->child = cJSON_CreateArray());
            }
        }
        else
        if(p->datatype == cJSON_String)
        {
            cJSON *t = cJSON_GetObjectItem(*p->root, p->fieldname);
            if(t)
                DEBUG("String exists! %s", p->fieldname);
            else
            {
                DEBUG("Add string: %s", p->fieldname);
                cJSON_AddStringToObject(*p->root, p->fieldname, p->fielddata);
            }
        }
        p++;
    }
}

const char *wan_devname()
{
    const char *mode = config_read_string("network.wan.mode");

    if(IS(mode, "pppoe"))
        return "pppv4";
    else if(IS(mode, "static"))
        return "eth1";
    else if(IS(mode, "dhcp"))
        return "eth1";

    return NULL;
}

// write to proc as a sysctl format
void sysctlwrite(char *path, int value)
{
    FILE *fp;
    char syspath[256], *p;

    if(strlen(path) + 10 > 255)
        print_log("sysctlwrite: path is too long\n");

    strcpy(syspath, "/proc/sys/");

    p = syspath + 10;
    while(*path)
    {
        if(*path == '.')
            *p = '/';
        else
            *p = *path;
        path++;
        p++;
    }
    *p = '\0';

    fp = fopen(syspath, "w");
    if(!fp)
    {
        print_log("Failed to open sysctl path %s\n", syspath);
        return;
    }

    fprintf(fp, "%d", value);
    fclose(fp);
}

//! write directly to proc files
void procwrite(char *path, char *value)
{
    FILE *fp;

    DEBUG("proc write %s: %s", path, value);

    fp = fopen(path, "w");
    if(!fp)
    {
        DEBUG("Failed to open path %s", path);
        return;
    }

    fprintf(fp, "%s\n", value);
    fclose(fp);
}

void print_log(char *fmt, ...)
{
    char buf[4096];
    FILE *f = fopen("/tmp/bergacli.log", "a+");
    //FILE *f = fopen("/dev/console", "w");

    va_list argp;
    va_start(argp, fmt);
    vsnprintf(buf, sizeof(buf), fmt, argp);

    fputs(buf, f);
    fclose(f);
}

bool save_configfile(const char *name, const char *fmt, ...)
{
    char *buf;

    va_list argp;
    va_start(argp, fmt);
    vasprintf(&buf, fmt, argp);

    write_textfile(name, buf, false);

    free(buf);

    return true;
}

bool concat_configfile(const char *name, const char *fmt, ...)
{
    char *buf;

    va_list argp;
    va_start(argp, fmt);
    vasprintf(&buf, fmt, argp);

    write_textfile(name, buf, true);

    free(buf);

    return true;
}

// save a text file, used for configuration files
bool write_textfile(const char *name, const char *txt, bool concat)
{
    FILE *f;

    f = fopen(name, concat?"a+":"w");

    if(!f)
    {
        print_log("Failed to open %s file!\n", name);
        return false;
    }
    
    fputs(txt, f);
    fclose(f);

    chmod(name, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);

    return true;
}

// returns true if a file exists
bool file_exists(const char *name)
{
    struct stat buffer;
    return (stat(name, &buffer) == 0);
}

// execute command using shell
void sysexec_shell(const char *fmt, ...)
{
    char *buf;

    va_list argp;
    va_start(argp, fmt);
    vasprintf(&buf, fmt, argp);

    DEBUG("shell_exec(%s)", buf);
    system(buf);

    free(buf);
}

void sysexec(bool wait, const char *name, char *fmt, ...)
{
    pid_t pid;
	int index = 1;
	char **token;
    char *buf;

    va_list argp;
    va_start(argp, fmt);
    vasprintf(&buf, fmt, argp);

	token = (char **)malloc(sizeof(void *) * 64);
    DEBUG("sysexec() %s %s", name, buf);

    if(buf)
    {
        *(token) = (char *)name;
        while((*(token+index) = strsep(&buf," ")))
            index++;
        *(token+index) = (char *)NULL;
    }
    else
    {
        *(token) = (char *)name;
        *(token+1) = (char *)NULL;
    }

    if(!wait)
    {
        // ignore children signal
        signal(SIGCHLD, SIG_IGN);
    }

    pid = fork();

    if(pid == 0)
    {
        int fd = open("/tmp/bergacli.log", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

        dup2(fd, 1);
        dup2(fd, 2);
        close(fd);

        //close(STDOUT_FILENO);
        //close(STDERR_FILENO);
        execvp(name, token);

        // should not reach, forked children code is replaced.
        print_log("WARNING: Failed to execv(%s %s)\n", name, buf);
        exit(-1);
    }
    else if(pid < 0)
        print_log("Failed to fork()\n");

    if(wait)
    {
        pid_t wpid;
        int waittime = 0;
        int stat;

        // wait until children process finishes
        do
        {
            wpid = waitpid(pid, &stat, WNOHANG);

            if(wpid == 0)
            {
                if(waittime < 600)
                {
                    DEBUG("Parent waiting %d second(s).", waittime);
                    usleep(100000);
                    waittime ++;
                }
                else
                {
                    DEBUG("Killing child process");
                    kill(pid, SIGKILL); 
                }
            }
        }
        while(wpid == 0 && waittime <= 600);

        if(WIFEXITED(stat))
        {
            DEBUG("Child exited, status=%d", WEXITSTATUS(stat));
        }
        else if(WIFSIGNALED(stat))
        {
            DEBUG("Child %d was terminated with a status of: %d", pid, WTERMSIG(stat));
        }
    }

    // release memory from parent process
    free(token);
    free(buf);
}

bool syskill(const char *name)
{
    DIR *dir;
    struct dirent *ent;
    char buf[256];
    FILE *file;
    bool killed = false;

    dir = opendir("/proc/");

    if(dir)
    {
        while((ent = readdir(dir)))
        {
            if(only_numbers(ent->d_name))
            {
                sprintf(buf, "/proc/%s/cmdline", ent->d_name);

                file = fopen(buf, "r");
                if(file)
                {
                    if(fread(buf, 1, sizeof(buf), file)>0)
                    {
                        fclose(file);

                        if(IS(buf, name))
                        {
                            DEBUG("killed process %s, PID: %s", name, ent->d_name);
                            kill(atoi(ent->d_name), SIGKILL);
                            killed = true;
                        }
                    }
                }
            }
        }

        closedir(dir);
    }

    if(killed)
        sleep(1);
    else
        DEBUG("could not kill %s, process not running. ", name);

    return true;
}

// remove blank spaces from string
char *remove_blanks(char *str)
{
    char *dest = str;
    char *ptr = dest;

    while(*str)
    {
        //while(*str == ' ' && *(str + 1) == ' ')
        while(*str == '\t' || *str == '\n' || *str == ' ')
            str++;

        *dest++ = *str++;
    }

    *dest = '\0';

    return ltrim(ptr);
}

char *remove_dots(char *str)
{
    char *dest = str;
    char *ptr = dest;

    while(*str)
    {
        while(*str == ':' || *str == '.')
            str++;

        *dest++ = *str++;
    }

    *dest = '\0';

    return ptr;
}

// right trim blanks
char *rtrim(char *string)
{
    char *original = string + strlen(string);
    while(*--original == ' ')
        ;
    *(original + 1) = '\0';
    return string;
}

// left trim blanks
char *ltrim(char *string)
{
    char *original = string;
    char *p = original;
    int trimmed = 0;
    do
    {
        if(*original != ' ' || trimmed)
        {
            trimmed = 1;
            *p++ = *original;
        }
    } while(*original++ != '\0');
    return string;
}

// search for a character on string
static inline int string_search_chr(char *token, char s)
{
    if(!token || s == '\0')
        return 0;

    for(; *token; token++)
        if(*token == s)
            return 1;

    return 0;
}

char *string_remove_chr(char *str, char *bad)
{
    char *src = str, *dst = str;
    while(*src)
    {
        if(string_search_chr(bad, *src))
            src++;
        else
            *dst++ = *src++; /* assign first, then incement */
    }

    *dst = '\0';
    return str;
}

/*
 * Copy string src to buffer dst of size dsize.  At most dsize-1
 * chars will be copied.  Always NUL terminates (unless dsize == 0).
 * Returns strlen(src); if retval >= dsize, truncation occurred.
 */
size_t strlcpy(char *dst, const char *src, size_t dsize)
{
    const char *osrc = src;
    size_t nleft = dsize;

    /* Copy as many bytes as will fit. */
    if(nleft != 0)
    {
        while(--nleft != 0)
        {
            if((*dst++ = *src++) == '\0')
                break;
        }
    }

    /* Not enough room in dst, add NUL and traverse rest of src. */
    if(nleft == 0)
    {
        if(dsize != 0)
            *dst = '\0'; /* NUL-terminate dst */
        while(*src++)
            ;
    }

    return (src - osrc - 1); /* count does not include NUL */
}

/*
 * Appends src to string dst of size dsize (unlike strncat, dsize is the
 * full size of dst, not space left).  At most dsize-1 characters
 * will be copied.  Always NUL terminates (unless dsize <= strlen(dst)).
 * Returns strlen(src) + MIN(dsize, strlen(initial dst)).
 * If retval >= dsize, truncation occurred.
 */
size_t strlcat(char *dst, const char *src, size_t dsize)
{
    const char *odst = dst;
    const char *osrc = src;
    size_t n = dsize;
    size_t dlen;

    /* Find the end of dst and adjust bytes left but don't go past end. */
    while(n-- != 0 && *dst != '\0')
        dst++;
    dlen = dst - odst;
    n = dsize - dlen;

    if(n-- == 0)
        return (dlen + strlen(src));
    while(*src != '\0')
    {
        if(n != 0)
        {
            *dst++ = *src;
            n--;
        }
        src++;
    }
    *dst = '\0';

    return (dlen + (src - osrc)); /* count does not include NUL */
}

char *ether_ntoa_rz(const struct ether_addr *addr, char *buf)
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr->ether_addr_octet[0], addr->ether_addr_octet[1],
            addr->ether_addr_octet[2], addr->ether_addr_octet[3],
            addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
    return buf;
}

char *ether_ntoa_z(const struct ether_addr *addr)
{
    static char buf[18];    /* 12 digits + 5 colons + null terminator */
    return ether_ntoa_rz(addr, buf);
}

void cpuload()
{
    long double a[4], b[4], loadavg;
    long double avg1, avg2;
    int percent = 0;
    FILE *fp;

    fp = fopen("/proc/stat","r");
    fscanf(fp,"%*s %Lf %Lf %Lf %Lf",&a[0],&a[1],&a[2],&a[3]);
    fclose(fp);
    sleep(1);

    fp = fopen("/proc/stat","r");
    fscanf(fp,"%*s %Lf %Lf %Lf %Lf",&b[0],&b[1],&b[2],&b[3]);
    fclose(fp);

    avg1 = (b[0]+b[1]+b[2]) - (a[0]+a[1]+a[2]);
    avg2 = (b[0]+b[1]+b[2]+b[3]) - (a[0]+a[1]+a[2]+a[3]);

    loadavg = avg1 / avg2;
    percent = round((99*avg1 + avg2/2)/avg2);

    openlog("cpuload", LOG_PID|LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "Current CPU load : %Lf (%d %%)\n", loadavg, percent);

    closelog();
}