#if defined(__APPLE__) && defined(__MACH__)
#include <os/log.h>
#include <os/signpost.h>

void os_log_with_type_rs(os_log_t log, os_log_type_t type, const char *message);

void os_signpost_interval_begin_rs(os_log_t log, os_signpost_id_t interval_id, const char *label);
void os_signpost_interval_end_rs(os_log_t log, os_signpost_id_t interval_id, const char *label);
#endif
