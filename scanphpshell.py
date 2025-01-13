import os
import fnmatch
import argparse
import hashlib
import stat
import pwd
import grp

class ShellDetector:
    _extensions = ["php"]  # Only PHP files

    def __init__(self, directory):
        self._directory = directory
        self._files = []
        self._search_terms = ["eval(", "gzinflate("]

    def list_files(self):
        """List all PHP files in the directory."""
        for root, _, filenames in os.walk(self._directory):
            for extension in self._extensions:
                for filename in fnmatch.filter(filenames, '*.' + extension):
                    self._files.append(os.path.join(root, filename))

    def calculate_md5(self, file_path):
        """Calculate MD5 hash of a file."""
        hasher = hashlib.md5()
        with open(file_path, 'rb') as file:
            for chunk in iter(lambda: file.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def get_file_info(self, file_path):
        """Get file owner, permissions, and other info."""
        file_stat = os.stat(file_path)
        try:
            owner = pwd.getpwuid(file_stat.st_uid).pw_name
            group = grp.getgrgid(file_stat.st_gid).gr_name
        except KeyError:
            owner = file_stat.st_uid
            group = file_stat.st_gid
        permissions = oct(file_stat.st_mode & 0o777)
        return f"{owner}:{group}", permissions

    def search_strings(self):
        """Search for specific strings in the files and write results in log format."""
        for file_path in self._files:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()
                for line_number, line_content in enumerate(lines, start=1):
                    for term in self._search_terms:
                        if term in line_content:
                            md5_hash = self.calculate_md5(file_path)
                            owner, permissions = self.get_file_info(file_path)
                            print(f"{file_path} {permissions} {owner} {md5_hash} Line:{line_number} FOUND:{term}")

    def start(self):
        self.list_files()
        self.search_strings()

# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan for suspicious PHP code.")
    parser.add_argument("directory", type=str, help="Directory to scan for PHP files.")
    args = parser.parse_args()

    detector = ShellDetector(directory=args.directory)
    detector.start()
