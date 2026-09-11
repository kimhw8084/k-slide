"""Download an authorized GitHub Actions artifact without leaking credentials.

GitHub's artifact endpoint returns a redirect to a signed object-storage URL.
The GitHub token is sent only to the approved GitHub API host; the redirect is
followed without that header and the completed archive is atomically installed
only after its digest matches the authoritative artifact digest.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import tempfile
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


class CertificationBundleDownloadError(ValueError):
    """Raised when an authorized artifact cannot be downloaded safely."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _digest(value: str) -> str:
    result = str(value or "").strip().lower()
    if result.startswith("sha256:"):
        result = result[7:]
    if len(result) != 64 or set(result) - set("0123456789abcdef"):
        raise CertificationBundleDownloadError("artifact digest is not a SHA-256 value")
    return result


def _repository_path(repository: str) -> str:
    parts = str(repository or "").strip().split("/")
    if len(parts) != 2 or any(not part or part in {".", ".."} for part in parts):
        raise CertificationBundleDownloadError("private source repository must be owner/name")
    return "/".join(quote(part, safe="") for part in parts)


def _api_url(api_base_url: str, repository: str, artifact_id: int) -> str:
    base = str(api_base_url or "").strip().rstrip("/")
    parsed = urlparse(base)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise CertificationBundleDownloadError("GitHub API base URL must be HTTPS without credentials")
    if isinstance(artifact_id, bool) or not isinstance(artifact_id, int) or artifact_id <= 0:
        raise CertificationBundleDownloadError("artifact id is invalid")
    return f"{base}/repos/{_repository_path(repository)}/actions/artifacts/{artifact_id}/zip"


def _redirect_url(current: str, location: str) -> str:
    target = urljoin(current, location)
    parsed = urlparse(target)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise CertificationBundleDownloadError("artifact redirect is not a safe HTTPS URL")
    if not parsed.netloc:
        raise CertificationBundleDownloadError("artifact redirect has no host")
    return target


def _open_without_redirect(opener: Any, request: Request) -> Any:
    try:
        return opener.open(request, timeout=60)
    except HTTPError as exc:
        if exc.code in {301, 302, 303, 307, 308}:
            location = exc.headers.get("Location")
            if not location:
                raise CertificationBundleDownloadError("artifact endpoint returned a redirect without a location") from exc
            return _redirect_url(request.full_url, location)
        raise CertificationBundleDownloadError(f"artifact download HTTP failure: {exc.code}") from exc
    except (OSError, URLError) as exc:
        raise CertificationBundleDownloadError("artifact download request failed") from exc


def download_artifact_archive(*, repository: str, artifact_id: int, output: Path, expected_sha256: str, token: str, api_base_url: str = "https://api.github.com", opener_factory: Callable[[], Any] | None = None) -> dict[str, str]:
    """Download one validated artifact and return non-sensitive digest metadata."""

    expected = _digest(expected_sha256)
    secret = str(token or "")
    if not secret:
        raise CertificationBundleDownloadError("private source credential is missing")
    output = output.expanduser().absolute()
    if output.exists() and output.is_symlink():
        raise CertificationBundleDownloadError("artifact output is symlinked")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        output.parent.chmod(0o700)
    except OSError as exc:
        raise CertificationBundleDownloadError("artifact output directory permissions could not be restricted") from exc
    opener = opener_factory() if opener_factory is not None else build_opener(_NoRedirect())
    api_endpoint = _api_url(api_base_url, repository, artifact_id)
    current = api_endpoint
    response: Any | None = None
    for hop in range(4):
        headers = {"Accept": "application/vnd.github+json"}
        if urlparse(current).netloc == urlparse(api_endpoint).netloc:
            headers["Authorization"] = f"Bearer {secret}"
        request = Request(current, headers=headers, method="GET")
        result = _open_without_redirect(opener, request)
        if isinstance(result, str):
            if hop == 3:
                raise CertificationBundleDownloadError("artifact download followed too many redirects")
            current = result
            continue
        response = result
        break
    if response is None:
        raise CertificationBundleDownloadError("artifact download did not return a response")
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".certification-bundle-", suffix=".zip", dir=output.parent)
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "wb") as stream:
            for block in iter(lambda: response.read(1024 * 1024), b""):
                if not isinstance(block, bytes):
                    raise CertificationBundleDownloadError("artifact download returned non-binary data")
                digest.update(block)
                stream.write(block)
            stream.flush()
            os.fsync(stream.fileno())
        actual = digest.hexdigest()
        if actual != expected:
            raise CertificationBundleDownloadError("downloaded artifact digest does not match the authoritative digest")
        os.replace(temporary, output)
        temporary = None
        output.chmod(0o600)
        return {"status": "PASS", "artifact_id": str(artifact_id), "sha256": actual}
    except (OSError, ValueError) as exc:
        if isinstance(exc, CertificationBundleDownloadError):
            raise
        raise CertificationBundleDownloadError("artifact archive could not be written safely") from exc
    finally:
        try:
            response.close()
        except (AttributeError, OSError):
            pass
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download and digest-check an authorized private certification artifact")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--artifact-id", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--token-env", default="GH_TOKEN")
    parser.add_argument("--api-base-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    args = parser.parse_args(argv)
    try:
        result = download_artifact_archive(repository=args.repository, artifact_id=args.artifact_id, output=args.output, expected_sha256=args.artifact_sha256, token=os.environ.get(args.token_env, ""), api_base_url=args.api_base_url)
    except CertificationBundleDownloadError as exc:
        print(f"artifact download BLOCKED: {exc}")
        return 2
    print(f"artifact download PASS: artifact_id={result['artifact_id']} sha256={result['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
