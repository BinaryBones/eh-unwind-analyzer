// Imports function ranges from CSV produced by:
//   eh_unwind_analyzer.exe target.exe --ghidra-csv ghidra_unwind.csv
//
// This Java version does not require PyGhidra/Jython.
//@author EH/Unwind Analyzer
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class ImportUnwindCsv extends GhidraScript {
	private static final String COMMENT_PREFIX = "[EH/Unwind Analyzer] ";
	private static final String BOOKMARK_CATEGORY = "EH/Unwind Analyzer";
	private static final int MAX_REPORTED_ERRORS = 25;

	private static long parseInteger(String text) {
		String value = text == null ? "" : text.trim();
		if (value.startsWith("0x") || value.startsWith("0X")) {
			return Long.parseUnsignedLong(value.substring(2), 16);
		}
		return Long.parseLong(value);
	}

	private static char detectDelimiter(String line) {
		int commas = 0;
		int semicolons = 0;
		boolean quoted = false;
		for (int i = 0; i < line.length(); i++) {
			char ch = line.charAt(i);
			if (ch == '"') {
				quoted = !quoted;
			}
			else if (!quoted && ch == ',') {
				commas++;
			}
			else if (!quoted && ch == ';') {
				semicolons++;
			}
		}
		return semicolons > commas ? ';' : ',';
	}

	private static List<String> parseCsvLine(String line, char delimiter) {
		ArrayList<String> out = new ArrayList<>();
		StringBuilder cell = new StringBuilder();
		boolean quoted = false;
		for (int i = 0; i < line.length(); i++) {
			char ch = line.charAt(i);
			if (quoted) {
				if (ch == '"') {
					if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
						cell.append('"');
						i++;
					}
					else {
						quoted = false;
					}
				}
				else {
					cell.append(ch);
				}
			}
			else if (ch == '"') {
				quoted = true;
			}
			else if (ch == delimiter) {
				out.add(cell.toString());
				cell.setLength(0);
			}
			else {
				cell.append(ch);
			}
		}
		out.add(cell.toString());
		return out;
	}

	private static String normalizeHeaderCell(String cell) {
		if (cell == null) {
			return "";
		}
		String value = cell.trim();
		if (!value.isEmpty() && value.charAt(0) == '\uFEFF') {
			value = value.substring(1).trim();
		}
		return value.toLowerCase();
	}

	private static Map<String, String> rowMap(List<String> header, List<String> row) {
		HashMap<String, String> map = new HashMap<>();
		for (int i = 0; i < header.size(); i++) {
			map.put(header.get(i), i < row.size() ? row.get(i) : "");
		}
		return map;
	}

	private static String field(Map<String, String> row, String name) {
		String value = row.get(name);
		return value == null ? "" : value.trim();
	}

	private static boolean isZeroLike(String value) {
		String v = value == null ? "" : value.trim();
		return v.isEmpty() || v.equals("0") || v.equals("0x0") || v.equals("0x00000000") ||
			v.equalsIgnoreCase("false") || v.equals("-");
	}

	private static String buildComment(Map<String, String> row, long beginRva, long endRva) {
		String importedComment = field(row, "comment");
		if (!importedComment.isEmpty()) {
			return importedComment;
		}

		ArrayList<String> parts = new ArrayList<>();
		String unwindVer = field(row, "unwind_ver");
		String unwindFlags = field(row, "unwind_flags");
		String unwindRva = field(row, "unwind_rva");
		if (!unwindVer.isEmpty() || !unwindFlags.isEmpty()) {
			parts.add("UNWIND v" + (unwindVer.isEmpty() ? "?" : unwindVer) +
				" flags=" + (unwindFlags.isEmpty() ? "0" : unwindFlags));
		}
		if (!unwindRva.isEmpty()) {
			parts.add("unwind_rva=" + unwindRva);
		}
		String prologSize = field(row, "prolog_size");
		String fixedStack = field(row, "fixed_stack");
		if (!prologSize.isEmpty() || !fixedStack.isEmpty()) {
			parts.add("prolog=" + (prologSize.isEmpty() ? "?" : prologSize) +
				" stack=" + (fixedStack.isEmpty() ? "?" : fixedStack) + "B");
		}
		String frameReg = field(row, "frame_reg");
		String frameOff = field(row, "frame_off");
		if (!frameReg.isEmpty() || !frameOff.isEmpty()) {
			parts.add("frame=" + (frameReg.isEmpty() ? "-" : frameReg) +
				"+" + (frameOff.isEmpty() ? "0" : frameOff));
		}
		String handlerRva = field(row, "handler_rva");
		if (!isZeroLike(handlerRva)) {
			parts.add("handler_rva=" + handlerRva);
		}
		String hasChain = field(row, "has_chain");
		if (!isZeroLike(hasChain)) {
			parts.add("has_chain=" + hasChain);
		}
		String anomalies = field(row, "anomalies");
		if (!isZeroLike(anomalies)) {
			parts.add("anomalies=" + anomalies);
		}
		String parseError = field(row, "parse_error");
		if (!parseError.isEmpty()) {
			parts.add("parse failed: " + parseError);
		}
		if (parts.isEmpty()) {
			parts.add(String.format("RUNTIME_FUNCTION 0x%08X..0x%08X", beginRva, endRva));
		}
		return String.join(" ", parts);
	}

	private static String analyzerComment(String existing, String importedComment) {
		String tagged = COMMENT_PREFIX + importedComment;
		if (existing == null || existing.isEmpty()) {
			return tagged;
		}
		StringBuilder kept = new StringBuilder();
		for (String line : existing.split("\\R")) {
			if (!line.startsWith(COMMENT_PREFIX)) {
				if (kept.length() > 0) {
					kept.append('\n');
				}
				kept.append(line);
			}
		}
		if (kept.length() > 0) {
			kept.append('\n');
		}
		kept.append(tagged);
		return kept.toString();
	}

	private static boolean canReplaceName(Function function) {
		SourceType source = function.getSymbol().getSource();
		return source == SourceType.DEFAULT || source == SourceType.ANALYSIS;
	}

	private List<Function> collectForeignOverlaps(FunctionManager functionManager, AddressSet body,
			Address ownEntry) {
		ArrayList<Function> result = new ArrayList<>();
		Iterator<Function> iterator = functionManager.getFunctionsOverlapping(body);
		while (iterator.hasNext()) {
			Function function = iterator.next();
			if (ownEntry == null || !function.getEntryPoint().equals(ownEntry)) {
				result.add(function);
			}
		}
		return result;
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		File csvFile = args.length > 0 ? new File(args[0])
				: askFile("Select EH/Unwind Analyzer Ghidra CSV", "Open");
		if (csvFile == null) {
			return;
		}

		long imageBase = currentProgram.getImageBase().getOffset();
		Memory memory = currentProgram.getMemory();
		Listing listing = currentProgram.getListing();
		FunctionManager functionManager = currentProgram.getFunctionManager();

		int created = 0;
		int updated = 0;
		int renamed = 0;
		int commented = 0;
		int bookmarked = 0;
		int skipped = 0;
		ArrayList<String> errors = new ArrayList<>();

		int transaction = currentProgram.startTransaction("Import EH/Unwind Analyzer ranges");
		boolean commit = false;
		try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(new FileInputStream(csvFile), StandardCharsets.UTF_8))) {
			String headerLine = reader.readLine();
			if (headerLine == null) {
				throw new IllegalArgumentException("CSV is empty");
			}
			char delimiter = detectDelimiter(headerLine);
			List<String> rawHeader = parseCsvLine(headerLine, delimiter);
			ArrayList<String> header = new ArrayList<>();
			for (String cell : rawHeader) {
				header.add(normalizeHeaderCell(cell));
			}
			if (!header.contains("begin_rva") || !header.contains("end_rva")) {
				throw new IllegalArgumentException(
					"CSV is missing required columns begin_rva and end_rva. Selected file: " +
					csvFile.getAbsolutePath() + ". First line was: " + headerLine);
			}
			if (!header.contains("name") || !header.contains("comment")) {
				println("[info] CSV has no name/comment columns; names and comments will be built from available report columns.");
			}

			String line;
			int rowNumber = 1;
			while ((line = reader.readLine()) != null) {
				rowNumber++;
				monitor.checkCancelled();
				if ((rowNumber % 100) == 0) {
					monitor.setMessage("Importing EH/Unwind row " + rowNumber);
				}

				try {
					Map<String, String> row = rowMap(header, parseCsvLine(line, delimiter));
					long beginRva = parseInteger(row.get("begin_rva"));
					long endRva = parseInteger(row.get("end_rva"));
					if (beginRva < 0 || endRva <= beginRva) {
						throw new IllegalArgumentException("invalid half-open range");
					}

					String functionName = row.get("name") == null ? "" : row.get("name").trim();
					if (functionName.isEmpty()) {
						functionName = String.format("sub_%08X", beginRva);
					}
					String comment = buildComment(row, beginRva, endRva);

					Address start = toAddr(imageBase + beginRva);
					Address end = toAddr(imageBase + endRva - 1);
					if (!memory.contains(start) || !memory.contains(end)) {
						throw new IllegalArgumentException("range is outside program memory");
					}

					AddressSet body = new AddressSet(start, end);
					Function function = functionManager.getFunctionAt(start);
					Function containing = functionManager.getFunctionContaining(start);
					if (function == null && containing != null) {
						throw new IllegalArgumentException(
							"entry lies inside existing function " + containing.getName());
					}

					List<Function> overlaps = collectForeignOverlaps(functionManager, body,
						function == null ? null : function.getEntryPoint());
					if (!overlaps.isEmpty()) {
						StringBuilder names = new StringBuilder();
						for (int i = 0; i < overlaps.size() && i < 3; i++) {
							if (i > 0) {
								names.append(", ");
							}
							names.append(overlaps.get(i).getName());
						}
						throw new IllegalArgumentException(
							"range overlaps existing function(s): " + names);
					}

					if (function == null) {
						function = listing.createFunction(functionName, start, body, SourceType.IMPORTED);
						if (function == null) {
							throw new IllegalStateException("Ghidra refused to create the function");
						}
						created++;
					}
					else {
						if (!function.getBody().equals(body)) {
							function.setBody(body);
						}
						updated++;
						if (!functionName.isEmpty() && !function.getName().equals(functionName) &&
							canReplaceName(function)) {
							function.setName(functionName, SourceType.IMPORTED);
							renamed++;
						}
					}

					if (!comment.isEmpty()) {
						String existingComment = getPreComment(start);
						setPreComment(start, analyzerComment(existingComment, comment));
						commented++;
						String lowered = comment.toLowerCase();
						if (lowered.contains("parse failed") || lowered.contains("anomalies=")) {
							currentProgram.getBookmarkManager().setBookmark(start, BookmarkType.WARNING,
								BOOKMARK_CATEGORY, comment);
							bookmarked++;
						}
					}
				}
				catch (Exception exc) {
					skipped++;
					if (errors.size() < MAX_REPORTED_ERRORS) {
						errors.add("row " + rowNumber + ": " + exc.getMessage());
					}
				}
			}
			commit = true;
		}
		finally {
			currentProgram.endTransaction(transaction, commit);
		}

		for (String message : errors) {
			println("[skip] " + message);
		}
		if (skipped > errors.size()) {
			println("[skip] " + (skipped - errors.size()) + " additional error(s) were not printed");
		}
		println("EH/Unwind import complete: created=" + created + " updated=" + updated +
			" renamed=" + renamed + " commented=" + commented + " bookmarks=" + bookmarked +
			" skipped=" + skipped);
	}
}
