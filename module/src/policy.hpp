#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>

struct NianchuTarget {
    unsigned uid;
    unsigned delay_ms;
    unsigned port;
    bool wait;
    char process[256];
};

static bool nianchu_number(const char *text, unsigned limit, unsigned *value)
{
    if (!text || !*text) return false;
    unsigned result = 0;
    for (const char *p = text; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        unsigned digit = unsigned(*p - '0');
        if (digit > limit || result > (limit - digit) / 10) return false;
        result = result * 10 + unsigned(*p - '0');
    }
    *value = result;
    return true;
}

static bool nianchu_process(const char *name)
{
    size_t length = strlen(name);
    if (!length || length >= 256 || !strchr(name, '.')) return false;
    for (size_t i = 0; i < length; ++i) {
        char c = name[i];
        if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') &&
            !(c >= '0' && c <= '9') && c != '_' && c != '.' && c != ':')
            return false;
    }
    return true;
}

/* Each row is: exact UID, exact process, delay_ms, port, wait|resume.
 * Validate the whole file before selecting; no wildcard or UID-only matches. */
static bool nianchu_select(char *text, size_t size, unsigned uid, const char *process,
                          NianchuTarget *selected, bool *found)
{
    *found = false;
    if (!text || size > 16384 || memchr(text, 0, size)) return false;
    text[size] = 0;
    NianchuTarget rows[64] = {};
    unsigned count = 0;
    char *cursor = text;
    while (*cursor) {
        char *line = cursor;
        char *end = strchr(cursor, '\n');
        if (end) { *end = 0; cursor = end + 1; }
        else cursor += strlen(cursor);
        size_t length = strlen(line);
        if (length && line[length - 1] == '\r') line[--length] = 0;
        while (*line == ' ' || *line == '\t') ++line;
        if (!*line || *line == '#') continue;
        if (count == 64) return false;
        char *fields[5] = {};
        unsigned n = 0;
        for (char *p = line; *p;) {
            if (n == 5) return false;
            fields[n++] = p;
            while (*p && *p != ' ' && *p != '\t') ++p;
            if (*p) *p++ = 0;
            while (*p == ' ' || *p == '\t') ++p;
        }
        if (n != 5) return false;
        NianchuTarget &row = rows[count];
        if (!nianchu_number(fields[0], INT_MAX, &row.uid) ||
            row.uid % 100000 < 10000 || row.uid % 100000 > 19999 ||
            !nianchu_process(fields[1]) ||
            !nianchu_number(fields[2], 60000, &row.delay_ms) ||
            !nianchu_number(fields[3], 65535, &row.port) || row.port < 1024)
            return false;
        if (!strcmp(fields[4], "wait")) row.wait = true;
        else if (!strcmp(fields[4], "resume")) row.wait = false;
        else return false;
        memcpy(row.process, fields[1], strlen(fields[1]) + 1);
        for (unsigned i = 0; i < count; ++i)
            if (rows[i].uid == row.uid && !strcmp(rows[i].process, row.process))
                return false;
        ++count;
    }
    for (unsigned i = 0; i < count; ++i) {
        if (rows[i].uid == uid && !strcmp(rows[i].process, process)) {
            *selected = rows[i];
            *found = true;
        }
    }
    return true;
}
