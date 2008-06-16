#include <linux/module.h>
#include <linux/version.h>

int starts_with(const char *str, const char *prefix);
int ends_with(const char *str, const char *suffix);
int label_offset(const char *sym_name);
const char *dup_wolabel(const char *sym_name);
