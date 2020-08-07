/*
   This file is part of Graphene Library OS.
   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.
   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * rune_pal_impl.c
 */

#include "rune_pal.h"
#include <libgen.h>

#define _GNU_SOURCE
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>

/*
 * NOTE: It's caller's responsibility to free the allocated string that return.
 */
char *resolve_absolute_uri(const char *uri, const char *dir)
{
    char *path = NULL, *path_uri = NULL;
    char *dirc = NULL;
    const char *errstring[CONFIG_MAX];

    if (!uri || !dir) {
        return NULL;
    }

    path_uri = resolve_uri(uri, (const char **)&errstring);
    if (!path_uri) {
        return NULL;
    }

    path = path_uri + URI_PREFIX_FILE_LEN;
    if (strstartswith_static(path, "/")) {
        // already a absolute path
        return path_uri;
    }

    dirc = alloc_concat(dir, (size_t)-1, "/", (size_t)-1);

    path = alloc_concat(dirc, (size_t)-1, path, (size_t)-1);
    free(dirc);

    path_uri = alloc_concat(URI_PREFIX_FILE, URI_PREFIX_FILE_LEN, path, (size_t)-1);
    free(path);

    return path_uri;
}

/*
 * NOTE: It's caller's responsibility to free the allocated string that return.
 */
char * resolve_manifest_uri(const char *exec_uri)
{
    char *manifest_uri = NULL, *manifest_full = NULL;
    char *dir = NULL, *dirc = NULL;
    int ret = 0;
    char manifest_base_name[URI_MAX];
    size_t manifest_base_name_len = sizeof(manifest_base_name);

    if (!exec_uri) {
        return NULL;
    }

    if (!strstartswith_static(exec_uri, URI_PREFIX_FILE)) {
        /* Invalid URI */
        return NULL;
    }

    ret = get_base_name(exec_uri + URI_PREFIX_FILE_LEN, manifest_base_name, &manifest_base_name_len);
    if (ret < 0) {
        return NULL;
    }

    if (!strendswith(manifest_base_name, ".manifest.sgx")) {
        if (!strcpy_static(manifest_base_name + manifest_base_name_len, ".manifest.sgx",
                           sizeof(manifest_base_name) - manifest_base_name_len)) {
            return NULL;
        }
    }

    // duplicate for dirname
    dirc = alloc_concat(exec_uri + URI_PREFIX_FILE_LEN, (size_t)-1, NULL, 0);
    dir = alloc_concat(dirname(dirc), (size_t)-1, "/", (size_t)-1);
    free(dirc);
    manifest_full = alloc_concat(dir, (size_t)-1, manifest_base_name, (size_t)-1);
    free(dir);
    manifest_uri = alloc_concat(URI_PREFIX_FILE, URI_PREFIX_FILE_LEN, manifest_full, (size_t)-1);
    SGX_DBG(DBG_I, "Manifest file: %s\n", manifest_uri);

    return manifest_uri;
}
