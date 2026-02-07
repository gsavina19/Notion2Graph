#!/usr/bin/env python3
"""
Build a per-page link map from an extracted Notion backup folder.

Usage:
    python 1-notion_link_graph.py /path/to/notion_export -o links.json
"""

from __future__ import annotations

import argparse
import html as html_lib
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote, urlsplit

PAGE_EXTENSIONS = {".md", ".html", ".htm"}
EXTERNAL_SCHEMES = {"http", "https", "mailto", "tel", "ftp", "sms"}
INTERNAL_LINK_KINDS = {"internal", "internal_fuzzy"}

MD_WIKILINK_RE = re.compile(r"\[\[([^\]]+)]]")
HTML_HREF_RE = re.compile(r"<a\s+[^>]*href=(['\"])(.*?)\1", re.IGNORECASE)
NOTION_ID_SUFFIX_RE = re.compile(r"[ \-_]?[0-9a-f]{32}$", re.IGNORECASE)
MD_H1_RE = re.compile(r"^\s*#\s+(.+?)\s*$", re.MULTILINE)
HTML_H1_RE = re.compile(r"<h1\b[^>]*>(.*?)</h1>", re.IGNORECASE | re.DOTALL)
HTML_TAG_RE = re.compile(r"<[^>]+>")


@dataclass(frozen=True)
class PageLink:
    raw: str
    kind: str
    target: str


def iter_page_files(root: Path) -> Iterable[Path]:
    for file_path in root.rglob("*"):
        if file_path.is_file() and file_path.suffix.lower() in PAGE_EXTENSIONS:
            yield file_path


def page_key(value: str) -> str:
    clean = unquote(value).replace("\\", "/")
    name = clean.rsplit("/", 1)[-1]
    stem = Path(name).stem
    stem = NOTION_ID_SUFFIX_RE.sub("", stem)
    stem = re.sub(r"[\s\-_]+", " ", stem).strip().lower()
    return stem


def default_page_title(rel_path: str) -> str:
    normalized = rel_path.replace("\\", "/")
    name = normalized.rsplit("/", 1)[-1]
    stem = Path(name).stem
    stem = NOTION_ID_SUFFIX_RE.sub("", stem).strip()
    return stem or name


def extract_page_title(text: str, suffix: str, rel_path: str) -> str:
    suffix = suffix.lower()

    if suffix == ".md":
        match = MD_H1_RE.search(text)
        if match:
            title = match.group(1).strip()
            if title:
                return title
    elif suffix in {".html", ".htm"}:
        match = HTML_H1_RE.search(text)
        if match:
            raw_title = HTML_TAG_RE.sub("", match.group(1))
            title = html_lib.unescape(raw_title).strip()
            if title:
                return title

    return default_page_title(rel_path)


def extract_markdown_links(text: str) -> list[str]:
    links: list[str] = []
    i = 0
    length = len(text)

    while i < length:
        if text[i] != "[":
            i += 1
            continue
        if i > 0 and text[i - 1] == "\\":
            i += 1
            continue

        # Find matching closing bracket for the link label, supporting nested [].
        j = i + 1
        bracket_depth = 1
        while j < length and bracket_depth > 0:
            ch = text[j]
            if ch == "\\":
                j += 2
                continue
            if ch == "[":
                bracket_depth += 1
            elif ch == "]":
                bracket_depth -= 1
            j += 1
        if bracket_depth != 0:
            i += 1
            continue

        # Skip optional whitespace between label and destination.
        k = j
        while k < length and text[k].isspace():
            k += 1
        if k >= length or text[k] != "(":
            i = j
            continue

        # Parse destination with balanced parentheses.
        k += 1
        while k < length and text[k].isspace():
            k += 1
        if k >= length:
            break

        if text[k] == "<":
            # Markdown permits destinations wrapped in <...>.
            k += 1
            start = k
            while k < length:
                ch = text[k]
                if ch == "\\":
                    k += 2
                    continue
                if ch == ">":
                    break
                k += 1
            if k >= length:
                i = j
                continue
            destination = text[start:k].strip()
            k += 1
            while k < length and text[k].isspace():
                k += 1
            if k >= length or text[k] != ")":
                i = j
                continue
            if destination:
                links.append(destination)
            i = k + 1
            continue

        start = k
        paren_depth = 1
        destination_end = -1
        while k < length:
            ch = text[k]
            if ch == "\\":
                k += 2
                continue
            if ch == "(":
                paren_depth += 1
                k += 1
                continue
            if ch == ")":
                paren_depth -= 1
                if paren_depth == 0:
                    destination_end = k
                    break
                k += 1
                continue
            k += 1

        if destination_end == -1:
            i = j
            continue

        destination = text[start:destination_end].strip()
        if destination:
            links.append(destination)
        i = destination_end + 1

    return links


def extract_links(text: str, suffix: str) -> list[str]:
    links: list[str] = []
    suffix = suffix.lower()

    if suffix == ".md":
        links.extend(extract_markdown_links(text))
        links.extend(match.group(1).strip() for match in MD_WIKILINK_RE.finditer(text))
    elif suffix in {".html", ".htm"}:
        links.extend(match.group(2).strip() for match in HTML_HREF_RE.finditer(text))

    return [link for link in links if link]


def to_rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def dedupe_links(links: Iterable[PageLink]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, str]] = []
    for link in links:
        key = (link.raw, link.kind, link.target)
        if key in seen:
            continue
        seen.add(key)
        out.append({"raw": link.raw, "kind": link.kind, "target": link.target})
    return out


def resolve_target(
    raw_target: str,
    source: Path,
    root: Path,
    pages_by_abs: dict[Path, str],
    pages_by_key: dict[str, list[str]],
) -> PageLink:
    target = raw_target.strip().strip("<>").strip()
    if not target:
        return PageLink(raw=raw_target, kind="missing", target="")

    parsed = urlsplit(target)
    scheme = parsed.scheme.lower()

    if scheme in EXTERNAL_SCHEMES:
        return PageLink(raw=raw_target, kind="external", target=target)

    if target.startswith("#"):
        return PageLink(raw=raw_target, kind="anchor", target=target)

    if scheme and scheme not in {"file"}:
        return PageLink(raw=raw_target, kind="external", target=target)

    decoded_path = unquote(parsed.path or "")
    if not decoded_path and parsed.fragment:
        return PageLink(raw=raw_target, kind="anchor", target=f"#{parsed.fragment}")

    if decoded_path.startswith("/"):
        relative_candidate = decoded_path.lstrip("/\\")
        base_candidates = [root / relative_candidate]
    else:
        base_candidates = [source.parent / decoded_path, root / decoded_path]

    candidates: list[Path] = []
    seen: set[Path] = set()
    for base in base_candidates:
        variants = [base]
        if base.suffix == "":
            variants.extend(
                base.with_suffix(ext) for ext in (".md", ".html", ".htm")
            )
        for variant in variants:
            try:
                resolved = variant.resolve(strict=False)
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            candidates.append(resolved)

    for candidate in candidates:
        if candidate in pages_by_abs:
            return PageLink(raw=raw_target, kind="internal", target=pages_by_abs[candidate])
        if candidate.exists() and candidate.is_file():
            return PageLink(raw=raw_target, kind="asset", target=to_rel(candidate, root))

    fuzzy = page_key(decoded_path or target)
    fuzzy_matches = pages_by_key.get(fuzzy, [])
    if len(fuzzy_matches) == 1:
        return PageLink(raw=raw_target, kind="internal_fuzzy", target=fuzzy_matches[0])
    if len(fuzzy_matches) > 1:
        return PageLink(
            raw=raw_target,
            kind="ambiguous",
            target=", ".join(sorted(fuzzy_matches)),
        )

    missing_target = decoded_path or target
    return PageLink(raw=raw_target, kind="missing", target=missing_target)


def build_link_map(root: Path) -> dict:
    page_paths = sorted(iter_page_files(root))
    pages_by_abs: dict[Path, str] = {}
    pages_by_key: dict[str, list[str]] = defaultdict(list)

    for page in page_paths:
        resolved = page.resolve()
        rel = to_rel(page, root)
        pages_by_abs[resolved] = rel
        key = page_key(rel)
        if rel not in pages_by_key[key]:
            pages_by_key[key].append(rel)

    links_by_page: dict[str, list[dict[str, str]]] = {}
    all_links_by_page: dict[str, list[dict[str, str]]] = {}
    non_child_links_by_page: dict[str, list[dict[str, str]]] = {}
    page_titles: dict[str, str] = {}
    internal_edges: list[dict[str, str]] = []
    totals = defaultdict(int)
    child_totals = defaultdict(int)

    for page in page_paths:
        rel = to_rel(page, root)
        page_titles[rel] = default_page_title(rel)
        try:
            text = page.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            links_by_page[rel] = []
            all_links_by_page[rel] = []
            non_child_links_by_page[rel] = []
            continue

        page_titles[rel] = extract_page_title(text, page.suffix, rel)
        raw_links = extract_links(text, page.suffix)
        resolved_links = [
            resolve_target(link, page, root, pages_by_abs, pages_by_key)
            for link in raw_links
        ]
        deduped = dedupe_links(resolved_links)
        all_links_by_page[rel] = deduped

        child_links = [
            link for link in deduped if link["kind"] in INTERNAL_LINK_KINDS
        ]
        links_by_page[rel] = child_links
        non_child_links_by_page[rel] = [
            link for link in deduped if link["kind"] not in INTERNAL_LINK_KINDS
        ]

        for link in deduped:
            totals[link["kind"]] += 1
            if link["kind"] in INTERNAL_LINK_KINDS:
                child_totals[link["kind"]] += 1
                internal_edges.append(
                    {"source": rel, "target": link["target"], "raw": link["raw"]}
                )

    incoming_by_page: dict[str, int] = defaultdict(int)
    for edge in internal_edges:
        incoming_by_page[edge["target"]] += 1

    connected_pages: set[str] = set()
    for page, child_links in links_by_page.items():
        has_children = len(child_links) > 0
        has_parents = incoming_by_page.get(page, 0) > 0
        if has_children or has_parents:
            connected_pages.add(page)

    links_by_page = {
        page: links
        for page, links in links_by_page.items()
        if page in connected_pages
    }
    all_links_by_page = {
        page: links
        for page, links in all_links_by_page.items()
        if page in connected_pages
    }
    non_child_links_by_page = {
        page: links
        for page, links in non_child_links_by_page.items()
        if page in connected_pages
    }
    page_titles = {
        page: title
        for page, title in page_titles.items()
        if page in connected_pages
    }
    internal_edges = [
        edge
        for edge in internal_edges
        if edge["source"] in connected_pages and edge["target"] in connected_pages
    ]

    return {
        "root": str(root),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanned_page_count": len(page_paths),
        "page_count": len(connected_pages),
        "links_by_page": links_by_page,
        "all_links_by_page": all_links_by_page,
        "non_child_links_by_page": non_child_links_by_page,
        "page_titles": page_titles,
        "internal_edges": internal_edges,
        "child_totals": dict(sorted(child_totals.items())),
        "totals": dict(sorted(totals.items())),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze an extracted Notion backup folder and produce a file with "
            "all links for each page."
        )
    )
    parser.add_argument(
        "input_dir",
        type=Path,
        help="Path to the root folder of the extracted Notion backup.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("notion_links.json"),
        help="Output JSON file (default: notion_links.json).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.input_dir.expanduser().resolve()
    output = args.output.expanduser().resolve()

    if not root.exists() or not root.is_dir():
        print(f"Input directory not found or not a directory: {root}", file=sys.stderr)
        return 1

    result = build_link_map(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print(
        f"Done. Scanned {result['scanned_page_count']} pages, "
        f"kept {result['page_count']} connected pages."
    )
    print(f"Output written to: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
