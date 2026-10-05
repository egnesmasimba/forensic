#!/usr/bin/env python3
"""
Collect files under a folder.

  python conso.py [source_dir] [output.md]
  python conso.py [source_dir] --copy-to DEST

The first form writes a Markdown dump (consolidated.md) of every text page.
The second copies the tree into DEST, preserving relative paths — all files
except VCS/build junk, not only “editable” source.
"""

import argparse
import os
import shutil
import sys
from pathlib import Path

TEXT_EXTENSIONS = {
    '.py': 'python',
    '.pyi': 'python',
    '.js': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.html': 'html',
    '.htm': 'html',
    '.css': 'css',
    '.scss': 'scss',
    '.sass': 'sass',
    '.less': 'less',
    '.json': 'json',
    '.jsonc': 'json',
    '.xml': 'xml',
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.toml': 'toml',
    '.ini': 'ini',
    '.cfg': 'ini',
    '.conf': 'ini',
    '.config': 'ini',
    '.env': 'bash',
    '.md': 'markdown',
    '.mdx': 'markdown',
    '.rst': 'rst',
    '.txt': 'text',
    '.csv': 'csv',
    '.tsv': 'text',
    '.sh': 'bash',
    '.bash': 'bash',
    '.zsh': 'bash',
    '.bat': 'batch',
    '.cmd': 'batch',
    '.ps1': 'powershell',
    '.psm1': 'powershell',
    '.sql': 'sql',
    '.c': 'c',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.cpp': 'cpp',
    '.h': 'c',
    '.hh': 'cpp',
    '.hpp': 'cpp',
    '.hxx': 'cpp',
    '.inl': 'cpp',
    '.cs': 'csharp',
    '.java': 'java',
    '.kt': 'kotlin',
    '.go': 'go',
    '.rs': 'rust',
    '.rb': 'ruby',
    '.php': 'php',
    '.lua': 'lua',
    '.r': 'r',
    '.swift': 'swift',
    '.m': 'objectivec',
    '.mm': 'objectivec',
    '.vue': 'vue',
    '.svelte': 'svelte',
    '.graphql': 'graphql',
    '.proto': 'protobuf',
    '.cmake': 'cmake',
    '.gradle': 'groovy',
    '.dockerfile': 'dockerfile',
    '.gitignore': 'gitignore',
    '.gitattributes': 'gitattributes',
    '.editorconfig': 'ini',
    '.uproject': 'json',
    '.uplugin': 'json',
    '.upluginmanifest': 'json',
    '.target.cs': 'csharp',
    '.build.cs': 'csharp',
    '.ush': 'hlsl',
    '.usf': 'hlsl',
    '.hlsl': 'hlsl',
    '.glsl': 'glsl',
    '.shader': 'hlsl',
    '.wgsl': 'wgsl',
    '.unreal': 'unreal',
}

EDITABLE_NAMES = {
    'dockerfile',
    'makefile',
    'gnumakefile',
    'cmakelists.txt',
    'license',
    'licence',
    'copying',
    'authors',
    'contributors',
    'changelog',
    'readme',
    'gemfile',
    'rakefile',
    'procfile',
    'vagrantfile',
    '.gitignore',
    '.gitattributes',
    '.gitmodules',
    '.editorconfig',
    '.dockerignore',
    '.npmrc',
    '.nvmrc',
    '.prettierrc',
    '.eslintrc',
    '.clang-format',
    '.clang-tidy',
    '.env',
    '.env.example',
    '.env.local',
    'cargo.lock',
    'package-lock.json',
}

# Only generated / VCS trees — do not skip source “pages” (Content, Config, docs).
SKIP_DIRS = {
    '.git',
    '.svn',
    '.hg',
    '__pycache__',
    '.pytest_cache',
    '.mypy_cache',
    '.ruff_cache',
    'node_modules',
    '.venv',
    'venv',
    '.idea',
    '.vs',
    '.vscode',
    '.cursor',
    'deriveddatacache',
    'intermediate',
    'binaries',
    'saved',
}

SKIP_FILE_NAMES = {
    'consolidated.md',
}

MAX_MARKDOWN_BYTES = 8 * 1024 * 1024


def _norm(name):
    return name.lower()


def is_skipped_dir(name):
    return _norm(name) in SKIP_DIRS or _norm(name).endswith('.egg-info')


def is_named_editable(path: Path):
    name = _norm(path.name)
    if name in EDITABLE_NAMES:
        return True
    if name.startswith('.env'):
        return True
    return False


def get_language(file_path: Path):
    name = _norm(file_path.name)
    if name.endswith('.build.cs') or name.endswith('.target.cs'):
        return 'csharp'
    ext = file_path.suffix.lower()
    return TEXT_EXTENSIONS.get(ext, '')


def is_binary_name(file_path: Path):
    return file_path.suffix.lower() in {
        '.uasset', '.umap', '.ubulk', '.uexp', '.pak', '.pdb', '.dll', '.exe',
        '.so', '.dylib', '.lib', '.obj', '.o', '.a', '.png', '.jpg', '.jpeg',
        '.gif', '.webp', '.ico', '.bmp', '.tga', '.psd', '.fbx', '.wav', '.mp3',
        '.ogg', '.mp4', '.mov', '.bin', '.zip', '.7z', '.rar', '.gz', '.woff',
        '.woff2', '.ttf', '.otf',
    }


def is_text_page(file_path: Path):
    """True for UTF-8 (or near-UTF-8) pages that belong in the Markdown dump."""
    if _norm(file_path.name) in SKIP_FILE_NAMES:
        return False
    if is_binary_name(file_path):
        return False

    ext = file_path.suffix.lower()
    if ext in TEXT_EXTENSIONS or is_named_editable(file_path):
        return True

    try:
        size = file_path.stat().st_size
        if size == 0:
            return True
        if size > MAX_MARKDOWN_BYTES:
            return False
        with open(file_path, 'rb') as f:
            chunk = f.read(4096)
        if b'\0' in chunk:
            return False
        chunk.decode('utf-8')
        return True
    except Exception:
        return False


def fence_for(content: str) -> str:
    """Use a backtick run longer than any in the file so the page copies intact."""
    longest = 0
    i = 0
    n = len(content)
    while i < n:
        if content[i] != '`':
            i += 1
            continue
        j = i
        while j < n and content[j] == '`':
            j += 1
        longest = max(longest, j - i)
        i = j
    return '`' * max(3, longest + 1)


def iter_files(source_dir: Path, output_path: Path | None, pages_only: bool):
    source_dir = source_dir.resolve()
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = sorted(d for d in dirs if not is_skipped_dir(d))
        for file in sorted(files):
            full_path = Path(root) / file
            if output_path and full_path.resolve() == output_path:
                continue
            if _norm(full_path.name) in SKIP_FILE_NAMES:
                continue
            if pages_only and not is_text_page(full_path):
                continue
            try:
                if pages_only and full_path.stat().st_size > MAX_MARKDOWN_BYTES:
                    print(f"Skipping oversized file: {full_path.relative_to(source_dir)}")
                    continue
            except OSError:
                continue
            yield full_path, full_path.relative_to(source_dir)


def write_markdown(source_dir: Path, output_file: Path):
    output_path = output_file.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(output_path, 'w', encoding='utf-8') as out_f:
        out_f.write(f"# Consolidated Files from `{source_dir}`\n\n")
        out_f.write(f"Generated by: {os.path.basename(__file__)}\n\n")
        out_f.write("---\n\n")
        for full_path, rel_path in iter_files(source_dir, output_path, pages_only=True):
            out_f.write(f"## `{rel_path.as_posix()}`\n\n")
            try:
                with open(full_path, 'r', encoding='utf-8', errors='replace') as in_f:
                    content = in_f.read()
            except Exception as e:
                out_f.write(f"*Error reading file: {e}*\n\n")
                continue
            lang = get_language(full_path)
            ticks = fence_for(content)
            out_f.write(f"{ticks}{lang}\n")
            out_f.write(content)
            if not content.endswith('\n'):
                out_f.write('\n')
            out_f.write(f"{ticks}\n\n")
            count += 1
        out_f.write("---\n")
        out_f.write("*End of consolidated files.*\n")
    print(f"Wrote {count} pages to '{output_file}'")


def copy_tree(source_dir: Path, dest_dir: Path, editable_only: bool):
    dest_dir = dest_dir.resolve()
    source_dir = source_dir.resolve()
    if dest_dir == source_dir or source_dir in dest_dir.parents:
        print("Error: --copy-to must not be inside the source tree.", file=sys.stderr)
        sys.exit(1)
    dest_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for full_path, rel_path in iter_files(source_dir, None, pages_only=editable_only):
        target = dest_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(full_path, target)
        count += 1
        print(rel_path.as_posix())
    kind = "editable pages" if editable_only else "files"
    print(f"Copied {count} {kind} to '{dest_dir}'")


def main():
    parser = argparse.ArgumentParser(
        description="Dump every text page to Markdown, or copy the whole tree."
    )
    parser.add_argument(
        'source_dir',
        nargs='?',
        default='.',
        help="Root directory to scan (default: current directory)",
    )
    parser.add_argument(
        'output_file',
        nargs='?',
        default='consolidated.md',
        help="Markdown dump path when not using --copy-to (default: consolidated.md)",
    )
    parser.add_argument(
        '--copy-to',
        metavar='DEST',
        help="Copy files into DEST (keeps folder layout) instead of writing Markdown",
    )
    parser.add_argument(
        '--editable-only',
        action='store_true',
        help="With --copy-to, copy only text/source pages (old behavior)",
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir)
    if not source_dir.is_dir():
        print(f"Error: '{source_dir}' is not a valid directory.", file=sys.stderr)
        sys.exit(1)

    if args.copy_to:
        copy_tree(source_dir, Path(args.copy_to), editable_only=args.editable_only)
    else:
        write_markdown(source_dir, Path(args.output_file))


if __name__ == '__main__':
    main()
