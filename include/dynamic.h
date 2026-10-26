#pragma once
/*
  dynamic.h - Windows-only dynamic evidence collector (Debug API)

  Records UNWIND_INFO handler hits, VEH/VCH/UEF registrations and hits,
  dynamic function-table registrations, and first/second-chance exceptions.
*/

#include <stdint.h>
#include <stdbool.h>
#include "util.h"
#include "pe.h"
#include "unwind.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { DYNAMIC_MAX_EVENTS = 256 };

typedef struct DynamicEvent {
    char type[40];
    char module[64];
    uint32_t thread_id;
    uint32_t exception_code;
    bool first_chance;
    uint64_t address;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
} DynamicEvent;

typedef struct DynamicReport {
    bool enabled;
    bool ran;
    bool ok;
    bool timed_out;
    bool target_exited;
    uint32_t target_exit_code;

    uint32_t timeout_ms;
    uint32_t trace_steps;
    uint64_t runtime_image_base;

    bool instrumentation_complete;
    uint32_t modules_observed_peak;
    uint32_t module_refresh_failures;
    uint32_t module_list_truncations;
    uint32_t unwind_handlers_discovered;
    uint32_t breakpoint_set_attempts;
    uint32_t breakpoint_set_failures;
    uint32_t breakpoint_capacity_drops;
    uint32_t pending_rearm_failures;
    uint32_t breakpoint_rearm_failures;

    uint32_t exceptions_seen;
    uint32_t first_chance_seen;
    uint32_t second_chance_seen;

    uint32_t unwind_handler_bp_set;
    uint32_t unwind_handler_hits;

    uint32_t veh_registrations;
    uint32_t veh_hits;
    uint32_t vch_registrations;
    uint32_t vch_hits;
    uint32_t uef_set_calls;
    uint32_t uef_hits;

    uint32_t rtl_add_function_table_calls;
    uint32_t rtl_install_function_table_cb_calls;

    uint32_t event_count;
    uint32_t dropped_events;
    DynamicEvent events[DYNAMIC_MAX_EVENTS];

    /*
      Execution trace sampled after first handler hit (RIP/VA addresses).
      runtime_image_base is the loaded base of the main debuggee image when
      the collector reached CREATE_PROCESS_DEBUG_EVENT; report.c uses it to
      explain trace addresses as RVA/section in the HTML report.
    */
    uint32_t trace_count;
    uint64_t trace[256];

    /* Human readable details */
    StrBuf details;
} DynamicReport;

void dynamic_report_init(DynamicReport* dr);
void dynamic_report_free(DynamicReport* dr);

/*
  Run target under a debugger and collect evidence.

  - pe_path: path to target executable
  - child_argv/child_argc: optional args (may be NULL/0)
  - img/rf/us/us_ok: results of static parsing (used to set handler breakpoints)
  - rf_count: number of runtime functions
  - timeout_ms: hard timeout for debug loop
  - trace_steps: number of single-steps to record after handler hit (<=256 recommended)

  Returns true if the dynamic session ran (even if it found no evidence).
*/
bool dynamic_collect_windows(const char* pe_path,
                            const char* const* child_argv,
                            int child_argc,
                            const PeImage* img,
                            const RuntimeFunction* rf,
                            const UnwindSummary* us,
                            const bool* us_ok,
                            size_t rf_count,
                            uint32_t timeout_ms,
                            uint32_t trace_steps,
                            DynamicReport* out,
                            StrBuf* err);

#ifdef __cplusplus
}
#endif
