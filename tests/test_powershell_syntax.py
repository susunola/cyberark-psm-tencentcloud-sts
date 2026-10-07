"""Every PowerShell file must parse under the real PowerShell parser.

A syntax error in these files is otherwise reported only by the host that executes them:
`Install-Bridge.ps1` needs Windows and administrator rights, so a typo costs a CI round trip
on a runner nobody can reproduce locally. Parsing is cheap and platform-independent, and it
also covers the scripts that no test is able to execute at all.

This replaces the parse step that used to live in the workflow, which is what makes the
convention in tests/test_hardening.py load-bearing: a `shell: pwsh` step must invoke a file
under scripts/ rather than inline its statements, or this module cannot see them.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Runs the parser over every path given as an argument and reports file:line: message.
PARSER = """$ErrorActionPreference = 'Stop'
$Failed = @()
foreach ($Path in $args) {
    $Tokens = $null
    $ParseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$Tokens, [ref]$ParseErrors) | Out-Null
    foreach ($Issue in $ParseErrors) {
        $Failed += "${Path}:$($Issue.Extent.StartLineNumber): $($Issue.Message)"
    }
}
if ($Failed.Count) { $Failed | ForEach-Object { Write-Output $_ }; exit 1 }
"""


@unittest.skipUnless(shutil.which('pwsh'), 'parsing PowerShell needs pwsh on PATH')
class PowerShellSyntaxTests(unittest.TestCase):
    def test_every_script_parses(self):
        sources = sorted((ROOT / 'scripts').rglob('*.ps1'))
        self.assertTrue(sources, 'no PowerShell sources were found, which would make this check vacuous')
        with tempfile.TemporaryDirectory() as folder:
            parser = Path(folder) / 'parse.ps1'
            parser.write_text(PARSER, encoding='utf-8')
            parsed = subprocess.run(
                ['pwsh', '-NoProfile', '-NonInteractive', '-File', str(parser), *(str(source) for source in sources)],
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        self.assertEqual(parsed.returncode, 0, parsed.stdout + parsed.stderr)


if __name__ == '__main__':
    unittest.main()
