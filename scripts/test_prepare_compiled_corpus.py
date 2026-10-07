import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from prepare_compiled_corpus import prepare, project_source


class PrepareCorpusTests(unittest.TestCase):
    def test_line_markers_keep_project_headers_and_exclude_system_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "project"
            expanded = (
                '# 1 "<built-in>"\nint builtin;\n'
                f'# 1 "{root}/main.c"\nint project;\n'
                f'# 1 "{root}-sdk/header.h" 1 3\nint system;\n'
                '# 1 "include/api.h" 1\nint header;\n'
                f'# 2 "{root}/main.c" 2\nint tail;\n'
            )
            self.assertEqual(
                project_source(expanded, root, root),
                "int project;\nint header;\nint tail;\n",
            )

    @unittest.skipUnless(shutil.which("cc"), "requires a C preprocessor")
    def test_compilation_database_expands_macros_and_preserves_originals(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "source"
            root.mkdir()
            header = "#define CALL\nint CALL declared(void);\n"
            (root / "api.h").write_text(header)
            source = (
                '#include "api.h"\n'
                '#if ENABLED\nint CALL active(void) { return 1; }\n'
                '#else\nint CALL inactive(void) { return 0; }\n#endif\n'
            )
            (root / "main.c").write_text(source)
            database = base / "compile_commands.json"
            database.write_text(json.dumps([{
                "directory": str(base),
                "file": str(root / "main.c"),
                "arguments": [
                    "cc", "-DENABLED=1", "-I", str(root), "-o",
                    str(base / "main.o"), "-c", str(root / "main.c"),
                ],
            }]))
            output = base / "expanded"
            self.assertEqual(prepare(root, database, output), 1)
            expanded = (output / "main.c").read_text()
            self.assertIn("declared(void)", expanded)
            self.assertIn("active(void)", expanded)
            self.assertNotIn("inactive(void)", expanded)
            self.assertNotIn("CALL", expanded)
            self.assertEqual((root / "main.c").read_text(), source)
            self.assertEqual((root / "api.h").read_text(), header)
            self.assertFalse((base / "main.o").exists())
            with self.assertRaises(FileExistsError):
                prepare(root, database, output)

    @unittest.skipUnless(shutil.which("cc"), "requires a C preprocessor")
    def test_preprocessor_failure_is_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "source"
            root.mkdir()
            (root / "main.c").write_text('#error broken configuration\n')
            database = base / "compile_commands.json"
            database.write_text(json.dumps([{
                "directory": str(root), "file": "main.c",
                "command": "cc -c main.c -o main.o",
            }]))
            with self.assertRaises(subprocess.CalledProcessError):
                prepare(root, database, base / "expanded")

    @unittest.skipUnless(shutil.which("c++"), "requires a C++ preprocessor")
    def test_cpp_namespace_macros_use_the_configured_compiler(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "source"
            root.mkdir()
            (root / "main.cc").write_text(
                "#define BEGIN namespace fmt {\n#define END }\n"
                "BEGIN\nint f() { return VALUE; }\nEND\n"
            )
            database = base / "compile_commands.json"
            database.write_text(json.dumps([{
                "directory": str(root), "file": "main.cc",
                "command": "c++ -std=c++11 -DVALUE=7 -c main.cc -o main.o",
            }]))
            output = base / "expanded"
            self.assertEqual(prepare(root, database, output), 1)
            text = (output / "main.cc").read_text()
            self.assertIn("namespace fmt {", text)
            self.assertIn("return 7;", text)
            self.assertNotIn("BEGIN", text)
            self.assertFalse((root / "main.o").exists())

    @unittest.skipUnless(shutil.which("c++"), "requires a C++ compiler")
    def test_compiler_rejects_invalid_cpp_that_preprocessing_would_accept(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "source"
            root.mkdir()
            (root / "main.cc").write_text("int f() { return missing_name; }\n")
            database = base / "compile_commands.json"
            database.write_text(json.dumps([{
                "directory": str(root), "file": "main.cc",
                "command": "c++ -c main.cc -o main.o",
            }]))
            with self.assertRaises(subprocess.CalledProcessError):
                prepare(root, database, base / "expanded")


if __name__ == "__main__":
    unittest.main()
