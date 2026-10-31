import argparse
import ast
import logging
import os
import re
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Files that could not be read or decoded during this run. A failed
# file is not a clean file, so main reports each one as not scanned
# and exits 1 when this list is not empty.
scan_failures = []

LOG_LEVELS = ("info", "error", "warning", "debug", "critical")

def _contains_name(node):
    return any(isinstance(child, ast.Name) for child in ast.walk(node))

def _is_log_call(node):
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr not in LOG_LEVELS:
        return False
    receiver = func.value
    return isinstance(receiver, ast.Name) and receiver.id in ("logging", "logger")

def _message_is_risky(arg):
    # A bare name written straight to the log.
    if isinstance(arg, ast.Name):
        return True
    # An f-string holding a name.
    if isinstance(arg, ast.JoinedStr):
        return _contains_name(arg)
    # A percent build holding a name, or a string built by adding a name.
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Mod, ast.Add)):
        return _contains_name(arg)
    # A .format call holding a name in its arguments.
    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
        return any(_contains_name(item) for item in list(arg.args) + [kw.value for kw in arg.keywords])
    return False

def _call_is_risky(node):
    if not node.args:
        return False
    # The lazy form passes the format string and the value as separate
    # arguments, logging.info("... %s", user), and the logging module
    # treats that as the safe way to pass values, so it is not flagged.
    if len(node.args) >= 2 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return False
    return _message_is_risky(node.args[0])

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Scans code for potential log injection vulnerabilities.")
    parser.add_argument("filepath", help="Path to the file or directory to scan.")
    parser.add_argument("-l", "--log-level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO',
                        help="Set the logging level (default: INFO).")
    parser.add_argument("-o", "--output", help="Path to the output file for results.", required=False)
    return parser.parse_args()

def is_potentially_vulnerable(line):
    """
    Checks if a line of code is potentially vulnerable to log injection.
    This is a simplified example and can be expanded with more sophisticated checks.

    Args:
        line (str): The line of code to check.

    Returns:
        bool: True if the line is potentially vulnerable, False otherwise.
    """
    # One pattern per message-building style, with the receiver and
    # level factored out. The old list spelled out ten copies of the
    # percent style only, so the .format and f-string calls in this
    # tool's own bundled example were never flagged, even though that
    # example marked them vulnerable.
    # The [^)]* spans stop at the first closing paren, so a call whose
    # argument itself contains parentheses can be undermatched. That
    # is accepted here: this is a line heuristic, not a parser.
    call = r"(?:logging|logger)\.(?:info|error|warning|debug|critical)\("
    patterns = [
        call + r"[^)]*\%\s*[sdrf]",
        call + r"[^)]*\.format\s*\(",
        call + r"\s*f['\"]",
    ]

    for pattern in patterns:
      if re.search(pattern, line):
        return True
    return False

def scan_file(filepath, output_file=None):
    """
    Scans a single file for potential log injection vulnerabilities.

    Args:
        filepath (str): The path to the file to scan.
        output_file (str, optional): The file to write the results to. Defaults to None (prints to console).

    Returns:
        list: A list of tuples, where each tuple contains the line number and the vulnerable line.
    """
    vulnerabilities = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()
        lines = source.splitlines()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if _is_log_call(node) and _call_is_risky(node):
                i = node.lineno
                line = lines[i - 1].strip() if 0 < i <= len(lines) else ""
                vulnerabilities.append((i, line))
                log_message = f"Potential log injection vulnerability found in {filepath} at line {i}: {line}"
                logging.warning(log_message)
                if output_file:
                    with open(output_file, "a") as outfile:
                        outfile.write(log_message + "\n")
                else:
                    print(log_message)

    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        scan_failures.append(filepath)
        return []
    except Exception as e:
        logging.error(f"Error processing file {filepath}: {e}")
        scan_failures.append(filepath)
        return []
    return vulnerabilities

def scan_directory(dirpath, output_file=None):
    """
    Scans all Python files in a directory for potential log injection vulnerabilities.

    Args:
        dirpath (str): The path to the directory to scan.
        output_file (str, optional): The file to write the results to. Defaults to None (prints to console).

    Returns:
        list: A list of tuples, where each tuple contains the filepath, line number, and the vulnerable line.
    """
    vulnerabilities = []
    for root, _, files in os.walk(dirpath):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                file_vulnerabilities = scan_file(filepath, output_file)
                for line_number, line in file_vulnerabilities:
                    vulnerabilities.append((filepath, line_number, line))
    return vulnerabilities

def main():
    """
    Main function to execute the log injection analyzer.
    """
    args = setup_argparse()

    # Set the logging level based on the command-line argument
    logging.getLogger().setLevel(args.log_level)

    filepath = args.filepath
    output_file = args.output

    # Validate input file path
    if not os.path.exists(filepath):
        logging.error(f"Invalid file path: {filepath}")
        sys.exit(1)

    if os.path.isfile(filepath):
        logging.info(f"Scanning file: {filepath}")
        vulnerabilities = scan_file(filepath, output_file)
    elif os.path.isdir(filepath):
        logging.info(f"Scanning directory: {filepath}")
        vulnerabilities = scan_directory(filepath, output_file)
    else:
        logging.error(f"Invalid file path: {filepath}")
        sys.exit(1)

    for failed in scan_failures:
        print(f"Not scanned: {failed}")
        if output_file:
            with open(output_file, "a") as outfile:
                outfile.write(f"Not scanned: {failed}\n")

    # Findings exit 1, as the other scanners in this set do. Before
    # this the count was computed and then dropped, so a run that
    # found injection patterns and a clean run were indistinguishable
    # to a script checking the exit code. A file that failed to scan
    # also exits 1 instead of passing as clean.
    if vulnerabilities or scan_failures:
        sys.exit(1)

if __name__ == "__main__":
    # Example Usage:
    # python main.py example.py
    # python main.py example_directory/
    # python main.py example.py -l DEBUG
    # python main.py example.py -o output.txt
    main()

