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

#ifndef UTILS_H
#define	UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include "cjson.h"

#ifdef	__cplusplus
extern "C" {
#endif

extern cJSON *json_root;

typedef struct
{
    char *data;
    size_t size;
} memdata_t;

struct jsdata_t
{
    int datatype;
    cJSON **root;
    cJSON **child;
    char *fieldname;
    char *fielddata;
};

#define DEBUG(fmt, args...) print_log("[DEBUG] " fmt " [%s:%d %s()]\n", ##args, __FILE__, __LINE__, __FUNCTION__)
//#define DEBUG(fmt, args...)

#define IS(x,str) !strcmp(x,str)

#define CHOP(str) string_remove_chr(str, "\r\n\t")

int mw2dbm(float mw);
float dbm2mw(int dbm);

char *byte_units(unsigned long bytes);

char *get_wan_ipv4();
in_addr_t a_to_hl( char *ipstr );
bool addr_in_range(char *addr, char *net1, char *mask);
char *mac2ipaddr(char *macaddr);

bool valid_ipv4(const char *ipaddr);
bool valid_ipv6(const char *ipaddr);
bool valid_mac(const char *macaddr);

char *rtrim(char *string);
char *ltrim(char *string);

bool no_spaces(char *str);
bool only_numbers(char *str);
bool only_letters(char *str);
bool only_alphanumeric(char *str);
bool no_specialchars(char *str);
void replace_spaces(char *filename);
bool is_empty(char *str);
int directory_exists(const char *path);
int directory_create(const char *path);

char *hash_password(char *pass);
char *random_seed();
size_t read_file(char **data, const char *filename);

void config_open();
void config_close();
void config_save(bool commit);
void config_adapt();

void reboot();
void factorydefaults();
char *json_getvalue_string(cJSON *j, int pos, char *value);

cJSON *config_get_node(const char *cfgpath);
cJSON *config_get_node_id(const char *cfgpath, int which, char *name);

char *config_read_string(char *cfgpath);
bool config_item_active(char *cfgpath);
void config_write_string(char *cfgpath, char *value);
void config_write_integer(char *cfgpath, int value);
bool config_delete_item(const char *cfgpath, int which);
bool config_delete_array(const char *arraypath);
bool config_insert_item(const char *cfgpath, cJSON *item);
bool config_replace_item(const char *cfgpath, int which, cJSON *item);

const char *wan_devname();

char *config_read_string(char *cfgpath);
void sysctlwrite(char *path, int value);
void procwrite(char *path, char *fmt, ...);
void print_log(char *fmt, ...);
bool save_configfile(const char *name, const char *fmt, ...);
bool concat_configfile(const char *name, const char *fmt, ...);
bool write_textfile(const char *name, const char *txt, bool concat);
bool file_exists(const char *name);
void sysexec_shell(const char *fmt, ...);
void sysexec(bool wait, const char *name, char *fmt, ...);
bool syskill(const char *name);
char *remove_blanks(char *str);
char *remove_dots(char *str);
char *string_remove_chr(char *str, char *bad);

size_t strlcpy(char *dst, const char *src, size_t dsize);
size_t strlcat(char *dst, const char *src, size_t dsize);

char *ether_ntoa_z(const struct ether_addr *addr);

void cpuload();

#ifdef	__cplusplus
}
#endif

#endif	/* UTILS_H */

