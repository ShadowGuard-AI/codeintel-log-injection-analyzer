import argparse
import logging
import os
import re
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
            for i, line in enumerate(f, 1):
                if is_potentially_vulnerable(line):
                    vulnerabilities.append((i, line.strip()))
                    log_message = f"Potential log injection vulnerability found in {filepath} at line {i}: {line.strip()}"
                    logging.warning(log_message)
                    if output_file:
                        with open(output_file, "a") as outfile:
                            outfile.write(log_message + "\n")
                    else:
                        print(log_message)

    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return []
    except Exception as e:
        logging.error(f"Error processing file {filepath}: {e}")
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

    # Findings exit 1, as the other scanners in this set do. Before
    # this the count was computed and then dropped, so a run that
    # found injection patterns and a clean run were indistinguishable
    # to a script checking the exit code.
    if vulnerabilities:
        sys.exit(1)

if __name__ == "__main__":
    # Example Usage:
    # python main.py example.py
    # python main.py example_directory/
    # python main.py example.py -l DEBUG
    # python main.py example.py -o output.txt
    main()

