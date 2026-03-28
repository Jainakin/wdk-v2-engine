/*
 * WDK v2 Native Engine — BIP-44 Implementation
 *
 * Path parsing and construction for BIP-44 derivation paths.
 */

#include "bip44.h"

#include <string.h>
#include <stdio.h>

/* --------------------------------------------------------------------------
 * Parse a BIP-44 derivation path
 * -------------------------------------------------------------------------- */

int wdk_bip44_parse_path(const char *path, uint32_t *indices, int *count, int max_count)
{
    if (!path || !indices || !count)
        return -1;

    *count = 0;
    const char *p = path;

    /* Path must start with "m" or "M" */
    if (*p != 'm' && *p != 'M')
        return -1;
    p++;

    /* Expect "/" after "m" (unless this is just "m") */
    if (*p == '\0') {
        /* Just "m" with no derivation - zero-length path is valid */
        return 0;
    }

    if (*p != '/')
        return -1;
    p++;

    /* Parse each path component */
    while (*p != '\0') {
        if (*count >= max_count)
            return -2; /* Path too deep */

        /* Parse the numeric index */
        uint32_t idx = 0;
        int has_digits = 0;

        while (*p >= '0' && *p <= '9') {
            /* Check for overflow: idx * 10 + digit must fit in 31 bits
             * (bit 31 is reserved for the hardened flag) */
            uint64_t next = (uint64_t)idx * 10 + (uint64_t)(*p - '0');
            if (next > 0x7FFFFFFF)
                return -1; /* Index too large */

            idx = (uint32_t)next;
            has_digits = 1;
            p++;
        }

        if (!has_digits)
            return -1; /* Expected a number */

        /* Check for hardened marker: ' or h or H */
        if (*p == '\'' || *p == 'h' || *p == 'H') {
            idx |= WDK_BIP44_HARDENED;
            p++;
        }

        indices[*count] = idx;
        (*count)++;

        /* Expect "/" separator or end of string */
        if (*p == '/') {
            p++;
            /* Don't allow trailing slash */
            if (*p == '\0')
                return -1;
        } else if (*p != '\0') {
            return -1; /* Unexpected character */
        }
    }

    return 0;
}

/* --------------------------------------------------------------------------
 * Build a standard BIP-44 path string
 * -------------------------------------------------------------------------- */

int wdk_bip44_build_path(uint32_t coin_type, uint32_t account,
                          uint32_t change, uint32_t address_index,
                          char *out, size_t out_size)
{
    if (!out || out_size == 0)
        return -1;

    /* Validate parameters */
    if (change > 1)
        return -1; /* Change must be 0 or 1 */

    if (coin_type > 0x7FFFFFFF || account > 0x7FFFFFFF || address_index > 0x7FFFFFFF)
        return -1;

    /* Format: m/44'/<coin>'/<account>'/<change>/<address_index> */
    int n = snprintf(out, out_size, "m/%u'/%u'/%u'/%u/%u",
                     (unsigned)WDK_BIP44_PURPOSE,
                     (unsigned)coin_type,
                     (unsigned)account,
                     (unsigned)change,
                     (unsigned)address_index);

    if (n < 0 || (size_t)n >= out_size)
        return -2; /* Buffer too small */

    return 0;
}
