![The back room before any label is read: one quarantine tank large in the foreground with its water line clear and one fish holding still in bottle green water, the bench running back with further plain tanks, a specimen jar with its lid on, the open field notebook lying flat, and a plain shelf with more jars, with no lettering anywhere](intro-banner.png)

# codeintel-Log-Injection-Analyzer

Title block: the name above is set in BenchNine in bottle green on specimen cream, ruled as a specimen label. <img src="logo.png" alt="Small quarantine tank mark: one plain tank on a short stand, water line below the rim, one fish in the middle of the water, and a small blank label on the front glass" width="28"> The tank mark is kept small at each heading in this README, at punctuation size, as the theme entry directs.

![The back room of the aquarium: a row of plain tanks on a bench along the back wall, each holding one fish and each with a label on its front glass, a specimen jar at the end of the bench, an open field notebook beside it, and the one written name on the long specimen label fixed to the centre tank](banner.png)

![The quarantine row in three depths: jars at rest on the back shelf, water circulating through the nearest tank while the fish holds and turns once, a hand sweeping the bench with a brush in two strokes, and a microscope focus ring turning as its inset sharpens](scene.svg)

## Held Apart for Watching <img src="logo.png" alt="Small quarantine tank mark" width="28">

Scans code for potential log injection vulnerabilities by identifying unsanitized user input that is directly written to log files, allowing attackers to inject malicious log entries. - Focused on Tools for static code analysis, vulnerability scanning, and code quality assurance

![Major separator: a brush stroke sweeping the full width of the rule, brass on specimen cream](sep-heavy.svg)

## Install <img src="logo.png" alt="Small quarantine tank mark" width="28">
`git clone https://github.com/ShadowGuardAI/codeintel-log-injection-analyzer`

> **Quarantine notice tied to the bench rail: name flagged.** The install line above writes the organisation name without its hyphen. The repository lives under ShadowGuard-AI, and the corrected address is https://github.com/ShadowGuard-AI/codeintel-log-injection-analyzer. The line is preserved as printed and flagged here. The README gives no step after the clone, and none is added here.

![Minor separator: a short centred brush stroke with plain rule on either side, brass on specimen cream](sep-light.svg)

## Usage <img src="logo.png" alt="Small quarantine tank mark" width="28">
`./codeintel-log-injection-analyzer [params]`

> **Quarantine notice tied to the bench rail: unusable as printed.** The usage line above omits the required file path and cannot be run as shown. The true line is python3 main.py FILEPATH [-l LEVEL] [-o OUTPUT]. Buttons in the kit read Scan This Path, Set the Log Level, Write Results to a File, and Show Help. Headings read Held Apart for Watching, Calls This Scan Can See, Shapes That Are Reported, The Lazy Form Is Left Alone, Not Scanned Is Not Clean, and Findings by File and Line.

![Major separator: a brush stroke sweeping the full width of the rule, brass on specimen cream](sep-heavy.svg)

## Parameters <img src="logo.png" alt="Small quarantine tank mark" width="28">
- `-h`: Show help message and exit
- `-l`: No description provided
- `-o`: Path to the output file for results.

> **Quarantine notice tied to the bench rail: A Logger Under Another Name Is Not Seen.** A call counts as a log call only when the receiver is the name logging or the name logger and the method is one of info, error, warning, debug, or critical. A logger held under a different name is not seen, and a logger reached through self.logger is not seen. The parameter list above gives only the short forms, gives -l no description, and omits the positional path in full, although the parser gives both long forms, five permitted levels, and an INFO default. The file is parsed into a syntax tree and the scan walks that tree; it is not a line by line text search. A directory scan reads only files that end in .py, while a single file given directly is attempted whatever its ending is.

> **Quarantine notice tied to the bench rail: Results Are Appended, Never Cleared.** If an output file is named, findings are appended to it, opened in append mode for each finding, and it is never cleared first. A second run at the same path adds its findings below the first run findings. A file that cannot be read, decoded, or parsed is listed as not scanned, and a run with a failed file exits 1, as does a run with findings and a path that does not exist. A run with neither finishes without an exit call and ends at 0.

![Minor separator: a short centred brush stroke with plain rule on either side, brass on specimen cream](sep-light.svg)

## License <img src="logo.png" alt="Small quarantine tank mark" width="28">
Copyright (c) ShadowGuardAI

> **Quarantine notice tied to the bench rail: closing line counted.** The closing line above is the second use of the unhyphenated form in the file. No licence is named in the README and no terms are given. The absence is recorded and nothing is added.
