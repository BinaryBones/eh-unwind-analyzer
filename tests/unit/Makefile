CC ?= gcc
CFLAGS ?= -std=c17 -O2 -Wall -Wextra -Wpedantic
INCLUDES := -I../../include

UNWIND_SRCS := unit_unwind.c ../../src/unwind.c ../../src/pe.c ../../src/util.c
HEUR_SRCS := unit_heuristics.c ../../src/heuristics.c ../../src/unwind.c ../../src/pe.c ../../src/util.c
HEUR_MIT_SRCS := unit_heuristics_mitigations.c ../../src/heuristics.c ../../src/unwind.c ../../src/pe.c ../../src/util.c
HEUR_CTX_SRCS := unit_heuristics_context.c ../../src/heuristics.c ../../src/unwind.c ../../src/pe.c ../../src/util.c
HEUR_COMBO_SRCS := unit_heuristics_combos.c ../../src/heuristics.c ../../src/unwind.c ../../src/pe.c ../../src/util.c
CORE_EDGE_SRCS := unit_core_edges.c ../../src/heuristics.c ../../src/unwind.c ../../src/pe.c ../../src/util.c
REPORT_SRCS := unit_report_json.c ../../src/report.c ../../src/heuristics.c ../../src/unwind.c ../../src/pe.c ../../src/util.c ../../src/dynamic_win.c
REPORT_HTML_SRCS := unit_report_html.c ../../src/report.c ../../src/heuristics.c ../../src/unwind.c ../../src/pe.c ../../src/util.c ../../src/dynamic_win.c
MATRIX_SRCS := unit_matrix_report.c ../../src/report.c ../../src/heuristics.c ../../src/unwind.c ../../src/pe.c ../../src/util.c ../../src/dynamic_win.c

all: unit_unwind unit_heuristics unit_heuristics_mitigations unit_heuristics_context unit_heuristics_combos unit_core_edges unit_report_json unit_report_html unit_matrix_report

unit_unwind: $(UNWIND_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(UNWIND_SRCS)

unit_heuristics: $(HEUR_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(HEUR_SRCS)

unit_heuristics_mitigations: $(HEUR_MIT_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(HEUR_MIT_SRCS)

unit_heuristics_context: $(HEUR_CTX_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(HEUR_CTX_SRCS)

unit_heuristics_combos: $(HEUR_COMBO_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(HEUR_COMBO_SRCS)

unit_core_edges: $(CORE_EDGE_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(CORE_EDGE_SRCS)

unit_report_json: $(REPORT_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(REPORT_SRCS)

unit_report_html: $(REPORT_HTML_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(REPORT_HTML_SRCS)

unit_matrix_report: $(MATRIX_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(MATRIX_SRCS)

run: all
	./unit_unwind
	./unit_heuristics
	./unit_heuristics_mitigations
	./unit_heuristics_context
	./unit_heuristics_combos
	./unit_core_edges
	./unit_report_json
	./unit_report_html
	./unit_matrix_report

clean:
	rm -f unit_unwind unit_heuristics unit_heuristics_mitigations unit_heuristics_context unit_heuristics_combos unit_core_edges unit_report_json unit_report_html unit_matrix_report
	rm -f unit_report_test_output.json unit_report_test_output.html matrix_case1_test_output.json matrix_case2_test_output.json matrix_case3_test_output.json unit_empty_input.bin
	rm -rf *.dSYM
