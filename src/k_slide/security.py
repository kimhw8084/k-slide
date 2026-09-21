"""Input validation, safe archive inspection, and immutable source hashing."""

from __future__ import annotations

import hashlib
import io
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
MAX_NESTED_PACKAGE_DEPTH = 1

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


@dataclass
class _ArchiveBudget:
    """One resource budget shared by an outer package and its workbook parts."""

    member_count: int = 0
    expanded_bytes: int = 0

    def consume(self, info: zipfile.ZipInfo, name: str) -> None:
        self.member_count += 1
        if self.member_count > MAX_ARCHIVE_ENTRIES:
            raise _archive_error("Office archive has too many cumulative members.")
        if info.file_size < 0 or info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
            raise _archive_error("Office archive contains an oversized package member.")
        if name.casefold().endswith((".xml", ".rels")) and info.file_size > MAX_ARCHIVE_XML_BYTES:
            raise _archive_error("Office archive contains an oversized XML member.")
        if info.file_size and (info.compress_size <= 0 or info.file_size > info.compress_size * MAX_ARCHIVE_COMPRESSION_RATIO):
            raise _archive_error("Office archive contains a disproportionately compressed member.")
        self.expanded_bytes += info.file_size
        if self.expanded_bytes > MAX_ARCHIVE_BYTES:
            raise _archive_error("Office archives expand beyond the cumulative safety limit.")


def _archive_members(
    archive: zipfile.ZipFile,
    budget: _ArchiveBudget,
) -> tuple[list[zipfile.ZipInfo], dict[str, str], dict[str, zipfile.ZipInfo]]:
    infos = archive.infolist()
    if len(infos) > MAX_ARCHIVE_ENTRIES:
        raise _archive_error("Office archive has too many members.")
    names: dict[str, str] = {}
    members: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        name = _archive_member_name(info)
        name_key = name.casefold()
        if name_key in names:
            raise _archive_error("Office archive contains ambiguous duplicate members.")
        names[name_key] = name
        members[name_key] = info
        if stat.S_ISLNK((info.external_attr >> 16) & 0xFFFF):
            raise _archive_error("Office archive contains a symbolic link.")
        budget.consume(info, name)
    return infos, names, members


def _relationship_source_path(relationship_name: str) -> list[str]:
    parts = relationship_name.split("/")
    if len(parts) < 2 or parts[-2].casefold() != "_rels" or not parts[-1].casefold().endswith(".rels"):
        raise _archive_error("Office archive contains an invalid relationship part.")
    return parts[:-2]


def _resolve_relationship_target(relationship_name: str, target: str) -> str:
    value = target.strip()
    if not value or "\\" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise _archive_error("Office archive contains an unsafe relationship target.")
    resolved = _relationship_source_path(relationship_name)
    for part in value.split("/"):
        if part in {"", "."}:
            raise _archive_error("Office archive contains an ambiguous relationship target.")
        if part == "..":
            if not resolved:
                raise _archive_error("Office archive contains a relationship traversal.")
            resolved.pop()
        else:
            resolved.append(part)
    if not resolved:
        raise _archive_error("Office archive contains an empty relationship target.")
    return "/".join(resolved)


def _relationship_records(data: bytes) -> list[dict[str, str]]:
    root = _parse_package_xml(data, unsafe_dtd=True)
    if _local_name(root.tag) != "relationships":
        raise _archive_error("Office archive contains an invalid relationship part.")
    records: list[dict[str, str]] = []
    ids: set[str] = set()
    for relationship in root:
        if _local_name(relationship.tag) != "relationship":
            continue
        attributes = {key.rsplit("}", 1)[-1].casefold(): str(value) for key, value in relationship.attrib.items()}
        relationship_id = attributes.get("id", "").casefold()
        target = attributes.get("target", "")
        relationship_type = attributes.get("type", "").strip()
        if not relationship_id or relationship_id in ids or not target or not relationship_type:
            raise _archive_error("Office archive contains ambiguous relationship metadata.")
        ids.add(relationship_id)
        records.append(attributes)
    return records


def _inspect_relationships(
    data: bytes,
    *,
    relationship_name: str,
    names: dict[str, str],
    allow_chart_workbook: bool,
) -> set[str]:
    workbook_targets: set[str] = set()
    for attributes in _relationship_records(data):
        target = attributes["target"]
        target_mode = attributes.get("targetmode", "").strip().casefold()
        relationship_type = attributes["type"].rsplit("/", 1)[-1].casefold()
        if target_mode == "external" or _external_relationship_target(target):
            raise _archive_error("Office document contains an external relationship.")
        if relationship_type in {"oleobject", "control", "vbaproject"}:
            raise _archive_error("Office document contains active embedded content.")
        resolved = _resolve_relationship_target(relationship_name, target)
        resolved_key = resolved.casefold()
        if resolved_key not in names:
            raise _archive_error("Office archive contains a relationship to a missing part.")
        if relationship_type == "package":
            if not allow_chart_workbook or not resolved_key.endswith(".xlsx") or "/embeddings/" not in f"/{resolved_key}":
                raise _archive_error("Office document contains an unsafe embedded package.")
            if resolved_key in workbook_targets:
                raise _archive_error("Office document contains an ambiguous embedded workbook.")
            workbook_targets.add(names[resolved_key])
        elif resolved_key.endswith(".xlsx"):
            raise _archive_error("Office document contains an unapproved workbook relationship.")
    return workbook_targets


def _inspect_content_types(data: bytes) -> dict[str, str]:
    root = _parse_package_xml(data, unsafe_dtd=True)
    if _local_name(root.tag) != "types":
        raise KSlideError(ErrorCode.INPUT_CORRUPT, "Office archive contains invalid content type metadata.")
    overrides: set[str] = set()
    content_types: dict[str, str] = {}
    defaults: set[str] = set()
    for item in root.iter():
        name = _local_name(item.tag)
        attributes = {key.rsplit("}", 1)[-1].casefold(): value for key, value in item.attrib.items()}
        content_type = str(attributes.get("contenttype", "")).casefold()
        if any(marker in content_type for marker in ("macroenabled", "vbaproject", "activex", "oleobject", "ms-office")):
            raise _archive_error("Office document contains active content.")
        if name == "default":
            extension = str(attributes.get("extension", "")).casefold()
            if not extension or extension in defaults:
                raise _archive_error("Office archive contains ambiguous package metadata.")
            defaults.add(extension)
        if name == "override":
            part_name = str(attributes.get("partname", "")).lstrip("/").casefold()
            if not part_name or "\\" in part_name or any(part in {"", ".", ".."} for part in part_name.split("/")) or part_name in overrides:
                raise _archive_error("Office archive contains ambiguous package metadata.")
            overrides.add(part_name)
            content_types[part_name] = content_type
    return content_types


def _inspect_active_members(names: set[str], *, nested: bool = False) -> None:
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
        if Path(lowered).suffix in {".xlsm", ".xlam", ".xltm", ".docm", ".pptm"}:
            raise _archive_error("Office document contains macro-enabled content.")
        if nested and (Path(lowered).suffix in executable_extensions or Path(lowered).suffix == ".bin" or "/embeddings/" in f"/{lowered}"):
            raise _archive_error("Nested workbook contains active embedded content.")


def _inspect_nested_workbook(data: bytes, *, budget: _ArchiveBudget, depth: int) -> None:
    if depth > MAX_NESTED_PACKAGE_DEPTH:
        raise _archive_error("Office archive contains an unsupported nested package depth.")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as workbook:
            _, names, members = _archive_members(workbook, budget)
            required = {"[content_types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels"}
            if not required.issubset(names) or not any(name.startswith("xl/worksheets/") and name.endswith(".xml") for name in names):
                raise _archive_error("Embedded workbook is not a structurally valid OOXML workbook.")
            _inspect_active_members(set(names.values()), nested=True)
            content_types = _inspect_content_types(workbook.read(members["[content_types].xml"]))
            relationship_files = [name for name in names.values() if name.casefold().endswith(".rels")]
            for relationship_name in relationship_files:
                _inspect_relationships(
                    workbook.read(members[relationship_name.casefold()]),
                    relationship_name=relationship_name,
                    names=names,
                    allow_chart_workbook=False,
                )
            workbook_name = names["xl/workbook.xml"]
            workbook_root = _parse_package_xml(workbook.read(members["xl/workbook.xml"]), unsafe_dtd=True)
            if _local_name(workbook_root.tag) != "workbook":
                raise _archive_error("Embedded workbook has an invalid workbook part.")
            workbook_content_type = content_types.get(workbook_name.casefold(), "")
            if not workbook_content_type.endswith("spreadsheetml.sheet.main+xml"):
                raise _archive_error("Embedded workbook has an invalid workbook content type.")
            relationships_name = names["xl/_rels/workbook.xml.rels"]
            relationship_data = workbook.read(members["xl/_rels/workbook.xml.rels"])
            relationships = _relationship_records(relationship_data)
            by_id = {record["id"]: record for record in relationships}
            sheets = [item for item in workbook_root.iter() if _local_name(item.tag) == "sheet"]
            if not sheets:
                raise _archive_error("Embedded workbook contains no worksheets.")
            worksheet_targets: set[str] = set()
            for sheet in sheets:
                relationship_id = next((value for key, value in sheet.attrib.items() if key.rsplit("}", 1)[-1].casefold() == "id"), "")
                record = by_id.get(relationship_id)
                if record is None or record["type"].rsplit("/", 1)[-1].casefold() != "worksheet":
                    raise _archive_error("Embedded workbook has an invalid worksheet relationship.")
                target_key = _resolve_relationship_target(relationships_name, record["target"]).casefold()
                if target_key not in names or not target_key.startswith("xl/worksheets/") or not target_key.endswith(".xml"):
                    raise _archive_error("Embedded workbook has an invalid worksheet target.")
                worksheet_targets.add(target_key)
            for worksheet_name in worksheet_targets:
                if not content_types.get(worksheet_name, "").endswith("worksheet+xml"):
                    raise _archive_error("Embedded workbook has an invalid worksheet content type.")
    except KSlideError:
        raise
    except (EOFError, OSError, OverflowError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        raise _archive_error("Embedded .xlsx content is not a readable OOXML workbook.") from exc


def _inspect_zip(path: Path, *, extension: str) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            budget = _ArchiveBudget()
            infos, names, members = _archive_members(archive, budget)
            if extension == ".pptx":
                if "[content_types].xml" not in names or "ppt/presentation.xml" not in names:
                    raise KSlideError(ErrorCode.INPUT_CORRUPT, "PPTX archive is missing presentation structure.")
                _inspect_active_members(set(names.values()))
                _inspect_content_types(archive.read(members["[content_types].xml"]))
                embedded_workbooks: set[str] = set()
                relationship_files = [info for info in infos if _archive_member_name(info).casefold().endswith(".rels")]
                for info in relationship_files:
                    relationship_name = _archive_member_name(info)
                    relationship_workbooks = _inspect_relationships(
                        archive.read(info),
                        relationship_name=relationship_name,
                        names=names,
                        allow_chart_workbook=True,
                    )
                    if embedded_workbooks.intersection(relationship_workbooks):
                        raise _archive_error("Office archive contains an ambiguous embedded workbook.")
                    embedded_workbooks.update(relationship_workbooks)
                actual_workbooks = {
                    name for name in names.values() if "/embeddings/" in f"/{name.casefold()}" and name.casefold().endswith(".xlsx")
                }
                if actual_workbooks != embedded_workbooks:
                    raise _archive_error("Office archive contains an unapproved embedded workbook.")
                for workbook_name in embedded_workbooks:
                    _inspect_nested_workbook(archive.read(members[workbook_name.casefold()]), budget=budget, depth=1)
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
