"""Chạy test Collector khi Python Store không ghi được vào %TEMP%.

Thư mục truyền qua --temp-dir phải tồn tại và rỗng. Runner chỉ xóa file do
test tạo trong thư mục đó; không đổi ACL hay xóa thư mục gốc được truyền vào.
"""

import argparse
from pathlib import Path
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ExistingTemporaryDirectory:
    """Context manager thay thế TemporaryDirectory bằng một thư mục rỗng có sẵn."""

    def __init__(self, directory: Path, *args, **kwargs):
        self.directory = directory

    def __enter__(self):
        return str(self.directory)

    def __exit__(self, exc_type, exc_value, traceback):
        remaining_directories = []
        for item in self.directory.iterdir():
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                remaining_directories.append(item)
        if remaining_directories:
            names = ", ".join(str(item) for item in remaining_directories)
            raise RuntimeError(f"Test để lại thư mục tạm chưa được dọn: {names}")
        return False


def run(temp_dir: Path) -> bool:
    """Nạp và chạy test_collector.py với TemporaryDirectory đã được thay thế."""
    if not temp_dir.is_dir():
        raise ValueError("--temp-dir phải là thư mục đã tồn tại")
    if any(temp_dir.iterdir()):
        raise ValueError("--temp-dir phải rỗng để không đụng dữ liệu có sẵn")
    original_temporary_directory = tempfile.TemporaryDirectory
    try:
        tempfile.TemporaryDirectory = lambda *args, **kwargs: ExistingTemporaryDirectory(
            temp_dir, *args, **kwargs,
        )
        suite = unittest.defaultTestLoader.discover(str(PROJECT_ROOT / "tests"), "test_collector.py")
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return result.wasSuccessful()
    finally:
        tempfile.TemporaryDirectory = original_temporary_directory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--temp-dir", required=True, type=Path, help="Thư mục rỗng đã tồn tại")
    args = parser.parse_args()
    try:
        return 0 if run(args.temp_dir.resolve()) else 1
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Collector test runner thất bại: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
