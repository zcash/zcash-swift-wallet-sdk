// v0.4 P0 bench-ios probe — C interface (see ../src/lib.rs for the contract).
#ifndef SLIPSTREAM_BENCH_H
#define SLIPSTREAM_BENCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SLIPSTREAM_BENCH_OK 0
#define SLIPSTREAM_BENCH_ERR_ARGS (-1)
#define SLIPSTREAM_BENCH_ERR_SYNC (-2)
#define SLIPSTREAM_BENCH_ERR_DIRTY_DIR (-3)
#define SLIPSTREAM_BENCH_ERR_BUFFER (-4)

// Run one fresh-restore bench pass; writes the engine BenchSummary JSON
// (NUL-terminated) into out_json. Blocking — call off the main thread.
// wallet_dir must NOT already contain a data.db (pass a new subdir per run).
// graft_subtree / batch_combine are the v0.4 levers (Plan A / Plan B);
// batch_decrypt is the v0.5 C1 lever (batched same-scalar trial-decrypt DH).
int32_t slipstream_bench_run(const char *server,
                             const char *ufvk,
                             uint32_t birthday,
                             const char *wallet_dir,
                             bool gpu_subtree,
                             bool graft_subtree,
                             bool batch_combine,
                             bool batch_decrypt,
                             bool endo_mul,
                             char *out_json,
                             size_t cap);

#endif
