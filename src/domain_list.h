#ifndef JAPONDPI_DOMAIN_LIST_H
#define JAPONDPI_DOMAIN_LIST_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct DomainNode {
    char              *domain;
    uint64_t           hash;
    struct DomainNode *next;
} DomainNode;

typedef struct {
    DomainNode **buckets;
    size_t       bucket_count;
    size_t       count;
} DomainList;

void   domain_list_init(DomainList *list);
bool   domain_list_add(DomainList *list, const char *domain);
bool   domain_list_load(DomainList *list, const char *filepath);
bool   domain_list_matches(const DomainList *list, const char *host);
void   domain_list_free(DomainList *list);

#endif /* JAPONDPI_DOMAIN_LIST_H */
