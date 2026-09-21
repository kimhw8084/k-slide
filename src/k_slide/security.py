"""Input validation, safe archive inspection, and immutable source hashing."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path

from .errors import ErrorCode, KSlideError
from .classification_policy import DEFAULT_CLASSIFICATION, validate_classification_label


MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 20_000
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = MAX_INPUT_BYTES
MAX_ARCHIVE_XML_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_COMPRESSION_RATIO = 200

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
    classification: str = DEFAULT_CLASSIFICATION

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        # The absolute source path is an intake-only capability, not product identity.
        value.pop("source_path", None)
        return value


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _archive_error(message: str) -> KSlideError:
    """Return a source-free archive error without echoing member names."""

    return KSlideError(ErrorCode.INPUT_ARCHIVE_UNSAFE, message)


def _archive_member_name(info: zipfile.ZipInfo) -> str:
    """Normalize a ZIP member name and reject aliases before any extraction."""

    raw = info.filename
    if "\x00" in raw or "\\" in raw or not raw:
        raise _archive_error("Office archive contains an unsafe member path.")
    if raw.startswith("/") or re.match(r"^[A-Za-z]:[/\\]", raw):
        raise _archive_error("Office archive contains an unsafe member path.")
    candidate = raw[:-1] if info.is_dir() and raw.endswith("/") else raw
    parts = candidate.split("/")
    if not candidate or any(part in {"", ".", ".."} for part in parts) or ":" in parts[0]:
        raise _archive_error("Office archive contains an unsafe member path.")
    return candidate


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].casefold()


def _parse_package_xml(data: bytes, *, unsafe_dtd: bool = False) -> ET.Element:
    lowered = data.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        if unsafe_dtd:
            raise _archive_error("Office archive contains an unsafe XML declaration.")
        raise KSlideError(ErrorCode.INPUT_CORRUPT, "Office archive contains malformed package XML.")
    try:
        return ET.fromstring(data)
    except (ET.ParseError, ValueError) as exc:
        raise KSlideError(ErrorCode.INPUT_CORRUPT, "Office archive contains malformed package XML.") from exc


def _external_relationship_target(target: str) -> bool:
    value = target.strip()
    return bool(
        value.startswith(("//", "\\\\"))
        or re.match(r"^[A-Za-z]:[/\\]", value)
        or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value)
    )


def _inspect_relationships(data: bytes) -> None:
    root = _parse_package_xml(data, unsafe_dtd=True)
    for relationship in root.iter():
        if _local_name(relationship.tag) != "relationship":
            continue
        attributes = {key.rsplit("}", 1)[-1].casefold(): value for key, value in relationship.attrib.items()}
        target = attributes.get("target", "")
        target_mode = attributes.get("targetmode", "").strip().casefold()
        relationship_type = attributes.get("type", "").rsplit("/", 1)[-1].casefold()
        if target_mode == "external" or _external_relationship_target(target):
            raise _archive_error("Office document contains an external relationship.")
        if relationship_type in {"oleobject", "control", "vbaproject"}:
            raise _archive_error("Office document contains active embedded content.")
        if relationship_type == "package" and not target.lower().endswith(".xlsx"):
            raise _archive_error("Office document contains an unsafe embedded package.")


def _inspect_content_types(data: bytes) -> None:
    root = _parse_package_xml(data, unsafe_dtd=True)
    overrides: set[str] = set()
    for item in root.iter():
        name = _local_name(item.tag)
        attributes = {key.rsplit("}", 1)[-1].casefold(): value for key, value in item.attrib.items()}
        content_type = str(attributes.get("contenttype", "")).casefold()
        if any(marker in content_type for marker in ("macroenabled", "vbaproject", "activex", "oleobject", "ms-office")):
            raise _archive_error("Office document contains active content.")
        if name == "override":
            part_name = str(attributes.get("partname", "")).lstrip("/").casefold()
            if not part_name or part_name in overrides:
                raise _archive_error("Office archive contains ambiguous package metadata.")
            overrides.add(part_name)


def _inspect_active_members(names: set[str]) -> None:
    executable_extensions = {
        ".app", ".bat", ".bin", ".cmd", ".com", ".dll", ".dmg", ".exe", ".hta", ".jar", ".js",
        ".jse", ".lnk", ".msi", ".ocx", ".ole", ".ps1", ".py", ".scr", ".sh", ".vbs", ".wsf",
        ".xla", ".xlam", ".xll", ".xlsm", ".docm", ".pptm",
    }
    for name in names:
        lowered = name.casefold()
        if lowered.endswith("vbaproject.bin") or "/activex/" in f"/{lowered}" or "/oleobjects/" in f"/{lowered}" or "/controls/" in f"/{lowered}":
            raise _archive_error("Office document contains active embedded content.")
        if "/embeddings/" in f"/{lowered}" and not lowered.endswith(".xlsx"):
            raise _archive_error("Office document contains an unsafe embedded object.")
        if "/embeddings/" in f"/{lowered}" and Path(lowered).suffix in executable_extensions:
            raise _archive_error("Office document contains an unsafe embedded object.")


def _inspect_zip(path: Path, *, extension: str) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                raise KSlideError(ErrorCode.INPUT_ARCHIVE_UNSAFE, "Office archive has too many entries.")
            total = 0
            names: dict[str, str] = {}
            for info in infos:
                name = _archive_member_name(info)
                name_key = name.casefold()
                if name_key in names:
                    raise _archive_error("Office archive contains ambiguous duplicate members.")
                names[name_key] = name
                if stat.S_ISLNK((info.external_attr >> 16) & 0xFFFF):
                    raise _archive_error("Office archive contains a symbolic link.")
                if info.is_dir():
                    continue
                if info.file_size > MAX_ARCHIVE_MEMBER_BYTES or info.file_size > MAX_ARCHIVE_XML_BYTES and name.casefold().endswith((".xml", ".rels")):
                    raise _archive_error("Office archive contains an oversized package member.")
                if info.file_size and (info.compress_size == 0 or info.file_size > info.compress_size * MAX_ARCHIVE_COMPRESSION_RATIO):
                    raise _archive_error("Office archive contains a disproportionately compressed member.")
                total += info.file_size
                if total > MAX_ARCHIVE_BYTES:
                    raise _archive_error("Office archive expands beyond the safety limit.")
            if extension == ".pptx":
                if "[content_types].xml" not in names or "ppt/presentation.xml" not in names:
                    raise KSlideError(ErrorCode.INPUT_CORRUPT, "PPTX archive is missing presentation structure.")
                _inspect_active_members(set(names))
                content_types = archive.read(next(info for info in infos if _archive_member_name(info).casefold() == "[content_types].xml"))
                _inspect_content_types(content_types)
                relationship_files = [info for info in infos if _archive_member_name(info).casefold().endswith(".rels")]
                for info in relationship_files:
                    _inspect_relationships(archive.read(info))
    except KSlideError:
        raise
    except (EOFError, OSError, OverflowError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        raise KSlideError(ErrorCode.INPUT_CORRUPT, "The Office archive is not readable.", {"reason": type(exc).__name__}) from exc


def _reject_symlink_components(path: Path) -> None:
    """Reject a symlink input; resolved containment handles parent escapes."""

    try:
        if path.expanduser().is_symlink():
            raise KSlideError(ErrorCode.INPUT_NOT_FOUND, "Input path may not be a symbolic link.")
    except OSError as exc:
        raise KSlideError(ErrorCode.INPUT_NOT_FOUND, "Input path could not be inspected safely.") from exc


def validate_input(
    path: Path,
    *,
    allowed_root: Path | None = None,
    logical_name: str | None = None,
    classification: str | None = None,
) -> InputArtifact:
    """Validate a supported source without trusting its filename."""

    original = path.expanduser()
    _reject_symlink_components(original)
    try:
        resolved = original.resolve(strict=True)
    except FileNotFoundError as exc:
        raise KSlideError(ErrorCode.INPUT_NOT_FOUND, "Input file does not exist.") from exc
    if allowed_root is not None:
        root = allowed_root.expanduser().resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise KSlideError(
                ErrorCode.PATH_OUTSIDE_ALLOWED_ROOT,
                "Input file is outside the allowed project root.",
            ) from exc
    if not resolved.is_file():
        raise KSlideError(ErrorCode.INPUT_NOT_FOUND, "Input path is not a regular file.")
    if not os.access(resolved, os.R_OK):
        raise KSlideError(ErrorCode.INPUT_NOT_FOUND, "Input file is not readable.")
    size = resolved.stat().st_size
    if size == 0:
        raise KSlideError(ErrorCode.INPUT_EMPTY, "Input file is empty.")
    if size > MAX_INPUT_BYTES:
        raise KSlideError(ErrorCode.INPUT_TOO_LARGE, "Input file exceeds the safety limit.", {"limit_bytes": MAX_INPUT_BYTES})

    display_name = logical_name or resolved.name
    if "\x00" in display_name or "/" in display_name or "\\" in display_name or display_name in {"", ".", ".."}:
        raise KSlideError(ErrorCode.INPUT_UNSUPPORTED, "Input logical name is not safe.")
    extension = Path(display_name).suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        raise KSlideError(ErrorCode.INPUT_UNSUPPORTED, "File type is not supported by K-Slide.", {"extension": extension})
    physical_extension = resolved.suffix.lower()
    if logical_name and physical_extension in SUPPORTED_EXTENSIONS and physical_extension != extension:
        raise KSlideError(ErrorCode.INPUT_TYPE_MISMATCH, "Input file extension does not match its host logical name.")
    with resolved.open("rb") as handle:
        header = handle.read(16)
    if extension in _MAGIC and not _MAGIC[extension](header):
        raise KSlideError(ErrorCode.INPUT_TYPE_MISMATCH, "File extension does not match its content.")
    if extension == ".pptx":
        _inspect_zip(resolved, extension=extension)

    kind = {".png": "image", ".jpg": "image", ".jpeg": "image", ".webp": "image", ".pdf": "pdf", ".pptx": "pptx"}[extension]
    effective_classification = validate_classification_label(classification) or DEFAULT_CLASSIFICATION
    return InputArtifact(
        source_path=str(resolved),
        source_name=display_name,
        extension=extension,
        kind=kind,
        size_bytes=size,
        sha256=sha256_file(resolved),
        classification=effective_classification,
    )
