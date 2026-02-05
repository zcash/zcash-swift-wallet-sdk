#include "wrapper.h"

#if defined(__APPLE__) && defined(__MACH__)
void os_log_with_type_rs(os_log_t log, os_log_type_t type, const char *message)
{
    os_log_with_type(log, type, "%{public}s", message);
}

void os_signpost_interval_begin_rs(os_log_t log, os_signpost_id_t interval_id, const char *label)
{
    os_signpost_interval_begin(log, interval_id, "rust", "%{public}s", label);
}

void os_signpost_interval_end_rs(os_log_t log, os_signpost_id_t interval_id, const char *label)
{
    os_signpost_interval_end(log, interval_id, "rust", "%{public}s", label);
}
#endif
