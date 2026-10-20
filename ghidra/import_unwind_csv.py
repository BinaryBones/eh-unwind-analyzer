#@author EH/Unwind Analyzer
#@category Analysis
#@keybinding
#@menupath
#@toolbar
#
# Import function ranges from CSV produced by:
#   eh_unwind_analyzer <file> --ghidra-csv unwind.csv
#
# The importer is conservative:
# - RVAs are resolved against the current program image base.
# - Existing user/imported names are preserved.
# - Overlapping functions are reported and skipped.
# - Existing comments are preserved outside the tagged analyzer line.
# - Parse failures and anomalies receive warning bookmarks.

import csv

from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import BookmarkType
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import CancelledException


REQUIRED_COLUMNS = set(["begin_rva", "end_rva", "name", "comment"])
COMMENT_PREFIX = "[EH/Unwind Analyzer] "
BOOKMARK_CATEGORY = "EH/Unwind Analyzer"
MAX_REPORTED_ERRORS = 25


def parse_integer(text):
    value = text.strip()
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    return int(value, 10)


def collect_foreign_overlaps(function_manager, body, own_entry):
    result = []
    iterator = function_manager.getFunctionsOverlapping(body)
    while iterator.hasNext():
        function = iterator.next()
        if own_entry is None or not function.getEntryPoint().equals(own_entry):
            result.append(function)
    return result


def analyzer_comment(existing, imported):
    tagged = COMMENT_PREFIX + imported
    if not existing:
        return tagged
    kept = []
    for line in existing.splitlines():
        if not line.startswith(COMMENT_PREFIX):
            kept.append(line)
    kept.append(tagged)
    return "\n".join(kept)


def can_replace_name(function):
    source = function.getSymbol().getSource()
    return source == SourceType.DEFAULT or source == SourceType.ANALYSIS


csv_file = askFile("Select EH/Unwind Analyzer Ghidra CSV", "Open")
csv_path = csv_file.getAbsolutePath()

image_base = currentProgram.getImageBase().getOffset()
memory = currentProgram.getMemory()
function_manager = currentProgram.getFunctionManager()
bookmark_manager = currentProgram.getBookmarkManager()

created = 0
updated = 0
renamed = 0
commented = 0
bookmarked = 0
skipped = 0
errors = []
commit = False
transaction = currentProgram.startTransaction("Import EH/Unwind Analyzer ranges")

try:
    with open(csv_path, "rb") as stream:
        reader = csv.DictReader(stream)
        columns = set(reader.fieldnames or [])
        missing = REQUIRED_COLUMNS.difference(columns)
        if missing:
            raise ValueError("CSV is missing required columns: %s" %
                             ", ".join(sorted(missing)))

        for row_number, row in enumerate(reader, 2):
            monitor.checkCancelled()
            if row_number % 100 == 0:
                monitor.setMessage("Importing EH/Unwind row %d" % row_number)

            try:
                begin_rva = parse_integer(row["begin_rva"])
                end_rva = parse_integer(row["end_rva"])
                if begin_rva < 0 or end_rva <= begin_rva:
                    raise ValueError("invalid half-open range")

                function_name = (row.get("name", "") or
                                 ("sub_%08X" % begin_rva)).strip()
                comment = (row.get("comment", "") or "").strip()
                start = toAddr(image_base + begin_rva)
                end = toAddr(image_base + end_rva - 1)
                if not memory.contains(start) or not memory.contains(end):
                    raise ValueError("range is outside program memory")

                body = AddressSet(start, end)
                function = function_manager.getFunctionAt(start)
                containing = function_manager.getFunctionContaining(start)
                if function is None and containing is not None:
                    raise ValueError("entry lies inside existing function %s" %
                                     containing.getName())

                overlaps = collect_foreign_overlaps(
                    function_manager,
                    body,
                    function.getEntryPoint() if function is not None else None,
                )
                if overlaps:
                    names = ", ".join(item.getName() for item in overlaps[:3])
                    raise ValueError("range overlaps existing function(s): %s" % names)

                if function is None:
                    function = function_manager.createFunction(
                        function_name,
                        start,
                        body,
                        SourceType.IMPORTED,
                    )
                    if function is None:
                        raise ValueError("Ghidra refused to create the function")
                    created += 1
                else:
                    if not function.getBody().equals(body):
                        function.setBody(body)
                    updated += 1
                    if (function_name and
                            function.getName() != function_name and
                            can_replace_name(function)):
                        function.setName(function_name, SourceType.IMPORTED)
                        renamed += 1

                if comment:
                    existing_comment = getPreComment(start)
                    setPreComment(start, analyzer_comment(existing_comment, comment))
                    commented += 1
                    lowered = comment.lower()
                    if "parse failed" in lowered or "anomalies=" in lowered:
                        bookmark_manager.setBookmark(
                            start,
                            BookmarkType.WARNING,
                            BOOKMARK_CATEGORY,
                            comment,
                        )
                        bookmarked += 1

            except CancelledException:
                raise
            except Exception as exc:
                skipped += 1
                if len(errors) < MAX_REPORTED_ERRORS:
                    errors.append("row %d: %s" % (row_number, str(exc)))

    commit = True
finally:
    currentProgram.endTransaction(transaction, commit)

for message in errors:
    print("[skip] %s" % message)
if skipped > len(errors):
    print("[skip] %d additional error(s) were not printed" %
          (skipped - len(errors)))

print("EH/Unwind import complete: created=%d updated=%d renamed=%d "
      "commented=%d bookmarks=%d skipped=%d" %
      (created, updated, renamed, commented, bookmarked, skipped))
