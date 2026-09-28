#!/usr/bin/env python3
"""Atheris fuzz harness for reorder-python-imports.

Feeds arbitrary fuzzer-generated Python source through fix_file_contents (the
library's core entry point: partition_source -> parse_imports ->
replace_imports -> remove_duplicated_imports -> apply_import_sorting), plus
fuzzer-derived to_add / to_remove / to_replace arguments, so libFuzzer reaches
the real tokenizer/parser/sorting code paths.

The library raises SyntaxError / ValueError for malformed source or malformed
import specs — those are expected, defined errors, not defects, so we catch
them and keep exploring. KeyError (classify_imports.import_obj_from_str hits an
AST node type it has no case for, e.g. via a fuzzer-derived to_add entry) is
the one genuine defect class this harness finds, so it always raises. The
original fuzz-imp harness suppressed it 99% of the time to keep a long fuzzing
campaign's corpus growing instead of re-crashing on every mutation; this
branch only ever replays a fixed, already-known crasher corpus once each
(mayhem.yml has no --duration), so that suppression would just make a genuine
defect fail to reproduce nondeterministically. Any other exception always
raises too — the original harness had no catch-all for it either.
"""

import os
import sys

# The module under test is a single root-level module (reorder_python_imports.py at the repo
# root); make it importable regardless of the launcher's cwd.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import atheris

import fuzz_helpers

with atheris.instrument_imports(include=['reorder_python_imports']):
    import reorder_python_imports as r


@atheris.instrument_func
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        to_add = fuzz_helpers.build_fuzz_tuple(fdp, [str])
        to_remove = fuzz_helpers.build_fuzz_set(fdp, [tuple, str])
        to_replace = r.Replacements.make([])
        r.fix_file_contents(
            fdp.ConsumeRemainingString(),
            to_add=to_add,
            to_remove=to_remove,
            to_replace=to_replace,
        )
    except (SyntaxError, ValueError):
        return


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
