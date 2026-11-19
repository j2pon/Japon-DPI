#include "domain_list.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define INITIAL_BUCKETS 4096

static uint64_t fnv1a_lower(const char *s, size_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)tolower((unsigned char)s[i]);
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h;
}

void domain_list_init(DomainList *list) {
    list->buckets = NULL;
    list->bucket_count = 0;
    list->count = 0;
}

bool domain_list_add(DomainList *list, const char *domain) {
    if (!list->buckets) {
        list->buckets = (DomainNode **)calloc(INITIAL_BUCKETS, sizeof(DomainNode *));
        if (!list->buckets) return false;
        list->bucket_count = INITIAL_BUCKETS;
    }

    size_t len = strlen(domain);
    if (len == 0) return true;

    uint64_t h = fnv1a_lower(domain, len);
    size_t idx = (size_t)(h & (list->bucket_count - 1));

    for (DomainNode *n = list->buckets[idx]; n; n = n->next) {
        if (n->hash == h && _stricmp(n->domain, domain) == 0) {
            return true; /* already present */
        }
    }

    DomainNode *node = (DomainNode *)malloc(sizeof(DomainNode));
    if (!node) return false;
    node->domain = (char *)malloc(len + 1);
    if (!node->domain) {
        free(node);
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        node->domain[i] = (char)tolower((unsigned char)domain[i]);
    }
    node->domain[len] = '\0';
    node->hash = h;
    node->next = list->buckets[idx];
    list->buckets[idx] = node;
    list->count++;
    return true;
}

bool domain_list_load(DomainList *list, const char *filepath) {
    FILE *f = fopen(filepath, "r");
    if (!f) return false;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Strip comments */
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';

        /* Trim leading whitespace and leading dots */
        char *p = line;
        while (*p && (isspace((unsigned char)*p) || *p == '.')) p++;

        /* Trim trailing whitespace and trailing dots */
        size_t len = strlen(p);
        while (len > 0 && (isspace((unsigned char)p[len - 1]) || p[len - 1] == '.')) {
            p[--len] = '\0';
        }

        if (len > 0 && len < 254) {
            domain_list_add(list, p);
        }
    }

    fclose(f);
    return true;
}

bool domain_list_matches(const DomainList *list, const char *host) {
    if (!list || !list->buckets || list->count == 0 || !host || !host[0]) {
        return false;
    }

    /* Check full host and parent suffixes (e.g. a.b.discord.com -> b.discord.com -> discord.com) */
    const char *cur = host;
    while (*cur) {
        size_t len = strlen(cur);
        uint64_t h = fnv1a_lower(cur, len);
        size_t idx = (size_t)(h & (list->bucket_count - 1));

        for (DomainNode *n = list->buckets[idx]; n; n = n->next) {
            if (n->hash == h && _stricmp(n->domain, cur) == 0) {
                return true;
            }
        }

        const char *dot = strchr(cur, '.');
        if (!dot || !dot[1]) break;
        cur = dot + 1;
    }
    return false;
}

void domain_list_free(DomainList *list) {
    if (!list || !list->buckets) return;
    for (size_t i = 0; i < list->bucket_count; i++) {
        DomainNode *n = list->buckets[i];
        while (n) {
            DomainNode *next = n->next;
            free(n->domain);
            free(n);
            n = next;
        }
    }
    free(list->buckets);
    list->buckets = NULL;
    list->bucket_count = 0;
    list->count = 0;
}
