"""ALL 2.0 (WP37): run-all verify-source. Listed installed files must match the MANIFEST's SHA-256; nothing else is checked. Nothing is sent.

Which manifest decides what a pass means. The one bundled in the install lives beside the files it lists: whoever can change an installed file can change that manifest, so a pass
against it proves only that the two agree, never that the files are the ones ALL published. The command says exactly that, prints the manifest's own SHA-256 and names the way to
compare with the published one (a manifest downloaded from the page, passed with --manifest, whose SHA-256 the page also shows). Only that second pass says "the published ones"."""
from __future__ import annotations

import glob
import hashlib
import json
from pathlib import Path
from typing import Any

PACKAGE_DIR = Path(__file__).resolve().parent.parent      # the all_mcp package this module is installed in
PREFIX = "src/all_mcp/"
BUNDLED_MANIFEST = PACKAGE_DIR / "encryption-source-manifest.json"
SCHEMA = "all-encryption-source/1"
EXIT_OK, EXIT_FAILED, EXIT_USAGE = 0, 1, 64

_TEXT = {
    "es": {
        "title": "Código publicado de ALL {version}: lo instalado",
        "version_bad": "Instalada: {installed}. El manifiesto es de la versión {version}; usa el de tu versión.",
        "no_manifest": "Esta copia no trae manifiesto. Usa: run-all verify-source --manifest RUTA (el de tu versión).",
        "bad_manifest": "No pude leer el manifiesto: no es uno de ALL válido o está dañado.",
        "changed": "Cambió: {path}",
        "missing": "Falta: {path}",
        "extra": "No está en el manifiesto: {path}",
        "manifest": "Manifiesto: {source} (SHA-256 {digest})",
        "source_bundled": "el que vino con esta instalación",
        "source_file": "el archivo que indicaste",
        "ok": "Correcto: los {count} archivos del manifiesto que corren en esta computadora coinciden con el manifiesto que indicaste. Compara el SHA-256 de arriba con el que muestra la página del código; si es el mismo, esos archivos son los publicados.",
        "ok_bundled": "Los {count} archivos del manifiesto que corren en esta computadora coinciden con el manifiesto que vino con esta instalación. Eso solo muestra que ambos concuerdan: quien pudiera cambiar un archivo podría cambiar también ese manifiesto. Para compararlos con lo publicado, baja el manifiesto de tu versión de la página del código y corre: run-all verify-source --manifest RUTA",
        "not_here": "{count} archivos del conjunto no corren en esta computadora. Este comando no los revisa.",
        "failed": "No coincide: {count} problema(s) en los archivos del manifiesto.",
        "usage": "uso: run-all verify-source [--manifest RUTA] [--json]",
    },
    "en": {
        "title": "Published code of ALL {version}: what is installed",
        "version_bad": "Installed: {installed}. The manifest is for {version}; use the one of your version.",
        "no_manifest": "This copy has no manifest. Use: run-all verify-source --manifest PATH (the one of your version).",
        "bad_manifest": "I could not read the manifest: it is not a valid ALL one or is damaged.",
        "changed": "Changed: {path}",
        "missing": "Missing: {path}",
        "extra": "Not in the manifest: {path}",
        "manifest": "Manifest: {source} (SHA-256 {digest})",
        "source_bundled": "the one that came with this install",
        "source_file": "the file you gave",
        "ok": "OK: the {count} files of the manifest that run on this computer match the manifest you gave. Compare the SHA-256 above with the one the code page shows; if it is the same, those files are the published ones.",
        "ok_bundled": "The {count} files of the manifest that run on this computer match the manifest that came with this install. That only shows the two agree: whoever could change a file could change that manifest too. To compare with what was published, download your version's manifest from the code page and run: run-all verify-source --manifest PATH",
        "not_here": "{count} files of the set do not run on this computer. This command does not check them.",
        "failed": "Does not match: {count} problem(s) in the files of the manifest.",
        "usage": "usage: run-all verify-source [--manifest PATH] [--json]",
    },
}


class ManifestError(Exception):
    """The _TEXT key that says why the manifest cannot be used."""


def _text(key: str, lang: str, **fields: Any) -> str:
    return _TEXT["en" if lang == "en" else "es"][key].format(**fields)


def manifest_sha256(path: Path | None = None) -> str:
    """The SHA-256 of the manifest file itself (the bundled one when `path` is None): the number the code page shows beside the manifest it publishes."""
    return hashlib.sha256((Path(path) if path is not None else BUNDLED_MANIFEST).read_bytes()).hexdigest()


def load_manifest(path: Path | None = None) -> dict[str, Any]:
    source = Path(path) if path is not None else BUNDLED_MANIFEST
    if not source.is_file():
        raise ManifestError("no_manifest")
    try:
        manifest = json.loads(source.read_text(encoding="utf-8"))
        if (manifest.get("schema") == SCHEMA and isinstance(manifest.get("allowlist"), list)
                and all(isinstance(e.get("path"), str) and isinstance(e.get("sha256"), str) for e in manifest["files"])):
            return manifest
    except (OSError, ValueError, AttributeError, TypeError, KeyError):
        pass
    raise ManifestError("bad_manifest")


def verify(manifest: dict[str, Any], *, installed_version: str, package_dir: Path = PACKAGE_DIR) -> dict[str, Any]:
    """`ok` only when the version matches, listed files run here and match, no allow-listed file is unlisted, and one file was checked."""
    listed = {entry["path"] for entry in manifest["files"]}
    out: dict[str, Any] = {"version": manifest.get("version"), "version_match": manifest.get("version") == installed_version,
                           "checked": [], "changed": [], "missing": [], "extra": [], "not_installed_here": []}
    for entry in manifest["files"]:
        rel = entry["path"]
        local = package_dir / rel[len(PREFIX):]
        if not rel.startswith(PREFIX):
            out["not_installed_here"].append(rel)
        elif not local.is_file():
            out["missing"].append(rel)
        else:
            out["checked"].append(rel)
            if hashlib.sha256(local.read_bytes()).hexdigest() != entry["sha256"]:
                out["changed"].append(rel)
    root = package_dir.resolve()
    withheld = {rel for rel in manifest.get("withheld", []) if isinstance(rel, str)}      # what the allow-list names and the export does not publish (the denylist): not an unlisted file
    for pattern in (p for p in manifest["allowlist"] if p.startswith(PREFIX)):
        for found in glob.glob(str(root / pattern[len(PREFIX):]), recursive=True, include_hidden=True):
            rel = PREFIX + Path(found).relative_to(root).as_posix()
            if Path(found).is_file() and rel not in listed and rel not in withheld and rel not in out["extra"]:
                out["extra"].append(rel)
    out["ok"] = bool(out["version_match"] and out["checked"] and not (out["changed"] or out["missing"] or out["extra"]))
    return out


def run(args: list[str], lang: str, *, installed_version: str | None = None,
        package_dir: Path = PACKAGE_DIR) -> tuple[int, list[str], dict[str, Any] | None]:
    """The command: (exit code, lines for the person's terminal, the report for --json)."""
    if installed_version is None:
        from .. import __version__ as installed_version  # noqa: N813 (the version this build runs)
    rest = [a for a in args if a != "--json"]
    if rest and not (len(rest) == 2 and rest[0] == "--manifest"):
        return EXIT_USAGE, [_text("usage", lang)], None
    given = Path(rest[1]).expanduser() if rest else None
    try:
        manifest = load_manifest(given)
        digest = manifest_sha256(given)
    except ManifestError as error:
        return EXIT_FAILED, [_text(str(error), lang)], None
    except OSError:
        return EXIT_FAILED, [_text("bad_manifest", lang)], None
    report = verify(manifest, installed_version=installed_version, package_dir=package_dir)
    report["manifest_source"] = "bundled" if given is None else "file"
    report["manifest_sha256"] = digest
    lines = [_text("title", lang, version=installed_version),
             _text("manifest", lang, source=_text("source_bundled" if given is None else "source_file", lang), digest=digest)]
    if not report["version_match"]:
        lines.append(_text("version_bad", lang, installed=installed_version, version=report["version"]))
    for key in ("changed", "missing", "extra"):
        lines += [_text(key, lang, path=p) for p in report[key]]
    if report["not_installed_here"]:
        lines.append(_text("not_here", lang, count=len(report["not_installed_here"])))
    as_json = report if "--json" in args else None
    if report["ok"]:
        return EXIT_OK, lines + [_text("ok_bundled" if given is None else "ok", lang, count=len(report["checked"]))], as_json
    problems = len(report["changed"]) + len(report["missing"]) + len(report["extra"]) + (0 if report["version_match"] else 1)
    return EXIT_FAILED, lines + [_text("failed", lang, count=max(problems, 1))], as_json
