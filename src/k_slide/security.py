"""Input validation, safe archive inspection, and immutable source hashing."""

from __future__ import annotations

import hashlib
import os
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

from .errors import ErrorCode, KSlideError


MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 20_000
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024

SUPPORTED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".pdf", ".pptx"}
_MAGIC = {
    ".png": lambda data: data.startswith(b"\x89PNG\r\n\x1a\n"),
    ".jpg": lambda data: data.startswith(b"\xff\xd8\xff"),
    ".jpeg": lambda data: data.startswith(b"\xff\xd8\xff"),
    ".webp": lambda data: data.startswith(b"RIFF") and data[8:12] == b"WEBP",
    ".pdf": lambda data: data.startswith(b"%PDF-"),
}


@dataclass(frozen=True)
class InputArtifact:
    source_path: str
    source_name: str
    extension: str
    kind: str
    size_bytes: int
    sha256: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _inspect_zip(path: Path, *, extension: str) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                raise KSlideError(ErrorCode.INPUT_ARCHIVE_UNSAFE, "Office archive has too many entries.")
            total = 0
            for info in infos:
                name = info.filename.replace("\\", "/")
                if name.startswith("/") or any(part == ".." for part in name.split("/")):
                    raise KSlideError(ErrorCode.INPUT_ARCHIVE_UNSAFE, "Office archive contains an unsafe path.", {"entry": name})
                if info.is_dir():
                    continue
                total += info.file_size
                if total > MAX_ARCHIVE_BYTES:
                    raise KSlideError(ErrorCode.INPUT_ARCHIVE_UNSAFE, "Office archive expands beyond the safety limit.")
                if ((info.external_attr >> 16) & 0o170000) == 0o120000:
                    raise KSlideError(ErrorCode.INPUT_ARCHIVE_UNSAFE, "Office archive contains a symbolic link.", {"entry": name})
            names = {info.filename for info in infos}
            if extension == ".pptx":
                if "[Content_Types].xml" not in names or "ppt/presentation.xml" not in names:
                    raise KSlideError(ErrorCode.INPUT_CORRUPT, "PPTX archive is missing presentation structure.")
                if any(name.lower().endswith("vbaproject.bin") for name in names):
                    raise KSlideError(ErrorCode.INPUT_ARCHIVE_UNSAFE, "Macro-enabled PowerPoint content is not accepted.")
    except KSlideError:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise KSlideError(ErrorCode.INPUT_CORRUPT, "The Office archive is not readable.", {"reason": str(exc)}) from exc


def validate_input(path: Path, *, allowed_root: Path | None = None) -> InputArtifact:
    """Validate a supported source without trusting its filename."""

    original = path.expanduser()
    if original.is_symlink():
        raise KSlideError(ErrorCode.INPUT_NOT_FOUND, "Input path may not be a symbolic link.", {"path": str(original)})
    try:
        resolved = original.resolve(strict=True)
    except FileNotFoundError as exc:
        raise KSlideError(ErrorCode.INPUT_NOT_FOUND, "Input file does not exist.", {"path": str(path)}) from exc
    if allowed_root is not None:
        root = allowed_root.expanduser().resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise KSlideError(
                ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT,
                "Input file is outside the allowed project root.",
                {"path": str(resolved), "root": str(root)},
            ) from exc
    if not resolved.is_file():
        raise KSlideError(ErrorCode.INPUT_NOT_FOUND, "Input path is not a regular file.", {"path": str(resolved)})
    if not os.access(resolved, os.R_OK):
        raise KSlideError(ErrorCode.INPUT_NOT_FOUND, "Input file is not readable.", {"path": str(resolved)})
    size = resolved.stat().st_size
    if size == 0:
        raise KSlideError(ErrorCode.INPUT_EMPTY, "Input file is empty.", {"path": str(resolved)})
    if size > MAX_INPUT_BYTES:
        raise KSlideError(ErrorCode.INPUT_TOO_LARGE, "Input file exceeds the safety limit.", {"limit_bytes": MAX_INPUT_BYTES})

    extension = resolved.suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        raise KSlideError(ErrorCode.INPUT_UNSUPPORTED, "File type is not supported by K-Slide.", {"extension": extension})
    with resolved.open("rb") as handle:
        header = handle.read(16)
    if extension in _MAGIC and not _MAGIC[extension](header):
        raise KSlideError(ErrorCode.INPUT_TYPE_MISMATCH, "File extension does not match its content.", {"path": str(resolved)})
    if extension == ".pptx":
        _inspect_zip(resolved, extension=extension)

    kind = {".png": "image", ".jpg": "image", ".jpeg": "image", ".webp": "image", ".pdf": "pdf", ".pptx": "pptx"}[extension]
    return InputArtifact(
        source_path=str(resolved),
        source_name=resolved.name,
        extension=extension,
        kind=kind,
        size_bytes=size,
        sha256=sha256_file(resolved),
    )
