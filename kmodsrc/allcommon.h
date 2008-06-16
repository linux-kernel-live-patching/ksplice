#include <linux/module.h>
#include <linux/version.h>

#define starts_with(str, prefix) (!strncmp(str, prefix, strlen(prefix)))
#define ends_with(str, suffix) (strlen(str) > strlen(suffix) && !strcmp(&str[strlen(str)-strlen(suffix)], suffix))

int label_offset(const char *sym_name);
const char *only_label(const char *sym_name);
const char *dup_wolabel(const char *sym_name);
