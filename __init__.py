"""
This plugin automates the process of generating pseudo C code from a binary
file, running Semgrep with custom rulesets, and presenting findings in an HTML
table. It seamlessly integrates within the Binary Ninja environment, allowing
users to perform the semgrep analysis without the need to exit Binary Ninja.
"""

from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, List, Optional, Tuple
import json
import re
import struct
import subprocess
import html

from tree_sitter import Language, Parser, Query
import emoji

from binaryninja import *


# directory path to the current script
CURRENT_DIR = Path(__file__).parent

# tree-sitter files
TREE_SITTER_C = CURRENT_DIR / "tree-sitter-c"
TREE_SITTER_LIB = CURRENT_DIR / "build" / "tree-sitter-c.so"

# query to search tree-sitter's syntax tree for illegal identifier annotations
FUNC_ANNOT_QUERY_STR = """
(function_definition
type: (primitive_type)
declarator: (function_declarator
    declarator: (identifier)
    parameters: (parameter_list)
    . (identifier) @annotation))
"""

# symbol types that are dumped in the pseudo C
DUMPED_SYMBOL_TYPES = (
    SymbolType.DataSymbol,
    SymbolType.ImportedDataSymbol,
    SymbolType.ExternalSymbol,
)

# regex for valid identifier syntax
VALID_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*")


def select_semgrep_rules() -> Optional[Path]:
    """Select a Semgrep rules file using a file dialog."""
    semgrep_rules = get_open_filename_input(
        "Select Semgrep rules:", "YAML (*.yml *.yaml)"
    )
    if semgrep_rules:
        return Path(semgrep_rules)

    log_info("No rules file selected")
    return None


def run_semgrep(in_file: str, out_file: str, rules: Path) -> Optional[list]:
    """
    Executes semgrep on the pseudo C code file, capturing and logging the
    output. Supports semgrep internal error handling for debugging purposes.
    """
    try:
        cmd = [
            "semgrep",
            "--verbose",
            "--no-git-ignore",
            f"--config={rules}",
            "--json",
            in_file,
            "--output",
            out_file,
        ]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)

        # log STDOUT and STDERR
        if result.stdout:
            log_info(f"Semgrep STDOUT: \n{result.stdout}")
        if result.stderr:
            log_info(f"Semgrep STDERR: \n{result.stderr}")

        with open(out_file, "r", encoding="utf-8") as inf:
            data = json.load(inf)
            return data.get("results", [])

    except subprocess.CalledProcessError as e:
        log_error(f"Semgrep failed with exit code {e.returncode}: {e.stderr}")
    except FileNotFoundError:
        log_error("Semgrep findings file not found")
    except json.JSONDecodeError:
        log_error("Failed to decode findings")

    return None


def get_code_at_line(pseudo_c: str, line_num: int) -> Optional[str]:
    lines = pseudo_c.split("\n")
    num_lines = len(lines)
    if line_num - 1 < num_lines:
        return lines[line_num - 1]
    return None


def process_semgrep_results(
    results: list, functions: List[Tuple[int, str]], line_offset: int
) -> str:
    """
    Process and link output of Semgrep analysis to addresses stored for code
    tracing.

    Returns the HTML report.
    """
    # map each address to a line number in the pseudo C code
    addr_to_line = {}
    for address, function in functions:
        addr_to_line[address] = line_offset
        line_offset += function.count("\n") + 1  # adds one for potential line breaks

    # generate and display report
    return build_html_report(results, functions, addr_to_line)


def build_html_report(
    results: list,
    functions: List[Tuple[int, str]],
    addr_to_line: Dict[int, int],
):
    """
    Builds the HTML table to display results from the Semgrep analysis.
    """
    report_html = """
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>Semgrep Vulnerability Findings</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #282c34;
            color: #abb2bf;
        }
        h3 {
            color: #61afef;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 10px;
            border: 1px solid #3e4451;
            text-align: left;
        }
        th {
            background-color: #3e4451;
            color: #56b6c2;
        }
        tr:nth-child(even) {
            background-color: #2c313c;
        }
        tr:hover {
            background-color: #3e4451;
        }
        a {
            color: #98c379;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
    </head>
    <body>
    <h3>Semgrep Vulnerability Findings</h3>
    <table>
    <thead>
        <tr>
            <th>Location</th>
            <th>Message</th>
            <th>Severity</th>
            <th>Code</th>
        </tr>
    </thead>
    <tbody>
    """
    for finding in results:
        message = finding.get("extra", {}).get("message", "No message provided")
        severity = finding.get("extra", {}).get("severity", "N/A")
        line_num = finding.get("start", {}).get("line")

        addr = "N/A"
        for addr, func in functions:
            start_line = addr_to_line[addr]
            num_lines = func.count("\n")
            if start_line <= line_num < start_line + num_lines + 1:
                addr = hex(addr)
                code_snippet = get_code_at_line(func, line_num - start_line)
                break

        code_snippet = (
            html.escape(code_snippet) if code_snippet else "Code not available"
        )

        # Format the HTML row
        report_html += f"""
        <tr>
            <td><a href="binaryninja://?expr={addr}">{addr}</a></td>
            <td>{message}</td>
            <td>{severity}</td>
            <td>{code_snippet}</td>
        </tr>
        """

    report_html += """
    </tbody>
    </table>
    </body>
    </html>
    """
    return report_html


class SemgrepAnalysis(BackgroundTaskThread):
    """Perform semgrep analysis on pseudo C produced by binary ninja."""

    bv: BinaryView
    disas_settings: DisassemblySettings
    parser: Parser
    func_annot_query: Query

    def __init__(self, bv):
        BackgroundTaskThread.__init__(
            self, "Running Semgrep Analysis...", can_cancel=True
        )

        self.bv = bv

        # configure psuedo C generation
        disas_settings = DisassemblySettings()
        disas_settings.set_option(DisassemblyOption.ShowAddress, False)
        disas_settings.set_option(DisassemblyOption.WaitForIL, True)
        self.linear_obj = LinearViewObject.language_representation(
            self.bv, disas_settings
        )

        # initialize tree-sitter
        if not TREE_SITTER_LIB.is_file():
            Language.build_library(str(TREE_SITTER_LIB), [str(TREE_SITTER_C)])
            if not TREE_SITTER_LIB.is_file():
                raise Exception("Failed to build tree-sitter lib")

        c_language = Language(str(TREE_SITTER_LIB), "c")
        self.parser = Parser()
        self.parser.set_language(c_language)
        self.func_annot_query = c_language.query(FUNC_ANNOT_QUERY_STR)

    def run(self):
        """
        The execution flow of the background analysis, handling the semgrep
        analysis process.
        """
        # load Semgrep rules
        semgrep_rules = select_semgrep_rules()
        if not semgrep_rules:
            log_error("No semgrep rules were provided")
            return

        # wrap everything in a try/except/finally block so the renamed
        # identifiers are always reverted
        renamed = False
        try:
            renamed = self.fix_identifiers()
            global_vars = self.get_global_variables()

            # generate pseudo C
            pseudo_c_funcs = [
                (func.start, self.get_pseudo_c(func)) for func in self.bv.functions
            ]

            # generate temp files for pseudo C code and semgrep findings
            with NamedTemporaryFile(
                suffix=".c", mode="w+"
            ) as pseudo_c_out, NamedTemporaryFile(
                suffix=".json", mode="w+"
            ) as semgrep_results_out:
                # serialise pseudo C contents
                for gv in global_vars:
                    pseudo_c_out.write(f"{gv}\n")
                for _, func in pseudo_c_funcs:
                    pseudo_c_out.write(f"{func}\n")

                # executes Semgrep on the pseudo C code
                results = run_semgrep(
                    pseudo_c_out.name, semgrep_results_out.name, semgrep_rules
                )

                if not results:
                    log_info("No Semgrep results")
                    return

            # construct and display Semgrep findings in HTML
            report = process_semgrep_results(results, pseudo_c_funcs, len(global_vars))
            self.bv.show_html_report("Semgrep Results", report)
        except:
            raise
        finally:
            if renamed:
                self.bv.undo()
                self.bv.reanalyze()

    def fix_identifiers(self) -> bool:
        """
        Renames invalid identifiers ("invalid" from the C standard). Invalid
        characters are replaced with "__". Renamed identifiers are updated in
        the binary view (so pseudo C can be generated), however, they are later
        reverted to avoid destructive renaming after performing psuedo-C dump.

        Returns `True` if an identifier was renamed.
        """
        renamed = False

        # track changes
        state = self.bv.begin_undo_actions()

        # global vars
        #
        # use a context manager to efficiently rename symbols. "Renaming"
        # symbols here means defining a new symbol and undefining the old
        # symbol.
        with self.bv.bulk_modify_symbols():
            for sym in self.bv.get_symbols():
                if sym.type not in DUMPED_SYMBOL_TYPES:
                    continue

                identifier = sym.name
                if not VALID_IDENTIFIER_RE.fullmatch(identifier):
                    new_identifier = re.sub(r"[^a-zA-Z0-9_]", "__", identifier)
                    new_sym = Symbol(
                        sym.type,
                        sym.address,
                        identifier,
                    )
                    self.bv.define_user_symbol(new_sym)
                    self.bv.undefine_user_symbol(sym)

                    renamed = True

        # local vars
        #
        # trigger a reanalysis of the function if a variable is renamed.
        for func in self.bv.functions:
            func_modified = False
            for var in func.vars:
                identifier = var.name
                if not VALID_IDENTIFIER_RE.fullmatch(identifier):
                    new_identifier = re.sub(r"[^a-zA-Z0-9_]", "__", identifier)
                    var.name = new_identifier

                    func_modified = True
                    renamed = True

            if func_modified:
                func.reanalyze()

        # commit changes
        self.bv.commit_undo_actions(state)

        return renamed

    def get_global_variables(self) -> List[str]:
        """
        Retrieves global variables using available symbol information, excluding
        function symbols, and ensuring symbols are handled correctly.
        """
        global_vars = []

        for sym in self.bv.get_symbols():
            if sym.type not in DUMPED_SYMBOL_TYPES:
                continue

            data_var = self.bv.get_data_var_at(sym.address)
            if not data_var:
                continue

            # construct the variable declaration
            pre = data_var.type.get_string_before_name()
            post = data_var.type.get_string_after_name()
            decl = f"{pre} {data_var.name} {post}"

            # TODO handle initial values for more-complex types
            if isinstance(data_var.value, (float, int, bool)):
                decl = f"{decl} = {data_var.value}"

            # add `extern`
            if sym.type in (
                SymbolType.ImportedDataSymbol,
                SymbolType.ExternalSymbol,
            ):
                decl = f"extern {decl}"

            global_vars.append(f"{decl};")

        return global_vars

    def get_pseudo_c(self, function) -> str:
        """
        The pseudo C code dump is based on the implementation available at
        https://github.com/AsherDLL/PCDump-bn/blob/main/__init__.py
        """
        cursor = LinearViewCursor(self.linear_obj)

        # collect the disassembled lines after and before the cursor's current
        # position, this effectively gathers the code associated with the
        # function pointed to
        cursor.seek_to_address(function.highest_address)
        body = self.bv.get_next_linear_disassembly_lines(cursor)
        cursor.seek_to_address(function.highest_address)
        header = self.bv.get_previous_linear_disassembly_lines(cursor)

        # sometimes binary ninja inserts emoji characters at the start of a
        # line. Strip these characters.
        #
        # XXX can this be done in tree-sitter
        pseudo_c = "\n".join(
            emoji.replace_emoji(str(line.contents), replace="")
            for line in header + body
        )

        return self.remove_function_annotations(pseudo_c)

    def remove_function_annotations(self, src: str) -> str:
        """
        Uses tree-sitter to locate invalid function annotations added by Binary
        Ninja. e.g., appending "__noreturn", "__pure" to a function definition.

        Any matches to the query string's like @annotation tags are removed,
        rest is kept the same.
        """
        tree = self.parser.parse(bytes(src, "utf8"))
        captures = self.func_annot_query.captures(tree.root_node)
        src_list = list(src)

        for node, _ in captures:
            # replace each annotation with the empty string
            for i in range(node.start_byte, node.end_byte):
                src_list[i] = ""

        # reconstruct source code from the list
        return "".join(src_list)


def run(bv):
    """
    This function starts the semgrep analysis background task.
    """
    SemgrepAnalysis(bv).start()


PluginCommand.register("Semgrep Analysis", "Run Semgrep over decompiled C", run)
