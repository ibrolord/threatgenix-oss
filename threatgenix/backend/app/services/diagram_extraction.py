"""Deterministic architecture-diagram extraction for uploaded PDFs."""

from __future__ import annotations

from dataclasses import dataclass
import itertools
import logging
import math
import re

import fitz  # PyMuPDF
import numpy as np

from app.schemas.document import DocumentParseResult, ParsedComponent, ParsedFlow
from app.services.doc_parser import normalize_extracted_text

logger = logging.getLogger(__name__)

try:
    from rapidocr_onnxruntime import RapidOCR
except Exception:  # pragma: no cover - optional dependency guard
    RapidOCR = None

_MIN_RECT_WIDTH = 72
_MIN_RECT_HEIGHT = 28
_MIN_RECT_AREA = 3_000
_MAX_LABEL_CHARS = 96
_MAX_OCR_LABEL_CHARS = 72
_LINE_TOLERANCE = 18
_DIAGRAM_DRAWING_THRESHOLD = 8
_LOW_TEXT_THRESHOLD = 220
_RASTER_RENDER_ZOOM = 2.0
_OCR_MIN_CONFIDENCE = 0.55
_CONNECTOR_DARK_RATIO = 0.12
_CONNECTOR_BAND = 4
_COMPONENT_HINT_RE = re.compile(
    r"\b(api|gateway|service|processor|engine|queue|broker|topic|database|db|vault|"
    r"store|cache|ledger|app|portal|client|partner|provider|worker|orchestrator|"
    r"user|admin|operator|analyst|system|bus)\b",
    re.IGNORECASE,
)
_IGNORE_OCR_RE = re.compile(
    r"^(figure|diagram|legend|notes?|page|\d+)$",
    re.IGNORECASE,
)
_DATA_STORE_HINT_RE = re.compile(
    r"\b(db|database|store|vault|ledger|cache|queue|repository|warehouse|lake)\b",
    re.IGNORECASE,
)
_HUMAN_ACTOR_HINT_RE = re.compile(
    r"\b(user|admin|operator|analyst|engineer|reviewer|developer|approver)\b",
    re.IGNORECASE,
)
_EXTERNAL_HINT_RE = re.compile(
    r"\b(client|partner|vendor|provider|third party|3rd party|external|browser|mobile app|system)\b",
    re.IGNORECASE,
)
_OCR_ENGINE = None
_OCR_ENGINE_READY = False


@dataclass(slots=True)
class _RasterComponentCandidate:
    page_rect: fitz.Rect
    pixel_rect: tuple[int, int, int, int]
    component: ParsedComponent


def raster_ocr_available() -> bool:
    """Return whether the optional OCR dependency is importable."""
    return RapidOCR is not None


def extract_diagram_parse_result(pdf_bytes: bytes) -> tuple[list[int], DocumentParseResult]:
    """Extract conservative component/flow candidates from diagrams in a PDF."""
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")

    components_by_name: dict[str, ParsedComponent] = {}
    flows_by_key: dict[tuple[str, str, str], ParsedFlow] = {}
    diagram_pages: set[int] = set()

    try:
        for page_index, page in enumerate(doc):
            page_number = page_index + 1
            page_text = normalize_extracted_text(page.get_text("text"))
            drawings = page.get_drawings()
            images = page.get_images(full=True)
            page_components = _extract_box_components(page, drawings, page_number)
            page_flows = _extract_connector_flows(
                drawings,
                {component.name: rect for rect, component in page_components},
                page_number,
            )

            raster_candidates: list[_RasterComponentCandidate] = []
            raster_flows: list[ParsedFlow] = []
            if not page_components and _looks_like_diagram_page(page_text, drawings, images):
                raster_candidates, raster_flows = _extract_raster_diagram_page(page, page_number)

            if page_components or raster_candidates or _looks_like_diagram_page(page_text, drawings, images):
                diagram_pages.add(page_number)

            for _, component in page_components:
                components_by_name.setdefault(component.name.lower(), component)
            for candidate in raster_candidates:
                components_by_name.setdefault(candidate.component.name.lower(), candidate.component)

            for flow in [*page_flows, *raster_flows]:
                key = (flow.source.lower(), flow.target.lower(), flow.label.lower())
                flows_by_key.setdefault(key, flow)
    finally:
        doc.close()

    return (
        sorted(diagram_pages),
        DocumentParseResult(
            components=list(components_by_name.values()),
            flows=list(flows_by_key.values()),
            boundaries=[],
            raw_text_excerpt="",
        ),
    )


def _looks_like_diagram_page(
    page_text: str,
    drawings: list[dict],
    images: list[tuple],
) -> bool:
    if len(drawings) >= _DIAGRAM_DRAWING_THRESHOLD and len(page_text) <= _LOW_TEXT_THRESHOLD:
        return True
    if images and len(page_text) <= _LOW_TEXT_THRESHOLD:
        return True
    return False


def _extract_box_components(
    page: fitz.Page,
    drawings: list[dict],
    page_number: int,
) -> list[tuple[fitz.Rect, ParsedComponent]]:
    components: list[tuple[fitz.Rect, ParsedComponent]] = []
    seen_labels: set[str] = set()

    for drawing in drawings:
        for item in drawing.get("items", []):
            if not item or item[0] != "re":
                continue
            rect = fitz.Rect(item[1])
            if rect.width < _MIN_RECT_WIDTH or rect.height < _MIN_RECT_HEIGHT:
                continue
            if rect.get_area() < _MIN_RECT_AREA:
                continue

            label = _extract_label_from_rect(page, rect)
            if not label:
                continue
            normalized_label = label.lower()
            if normalized_label in seen_labels:
                continue

            seen_labels.add(normalized_label)
            components.append(
                (
                    rect,
                    ParsedComponent(
                        name=label,
                        component_type=_infer_component_type(label),
                        confidence=0.9,
                        description=f"Extracted from a diagram shape on page {page_number}.",
                        extraction_source="diagram",
                        evidence_page=page_number,
                        evidence_snippet=label,
                    ),
                )
            )

    return components


def _extract_label_from_rect(page: fitz.Page, rect: fitz.Rect) -> str:
    text = normalize_extracted_text(page.get_text("text", clip=rect)).strip()
    if not text:
        expanded = fitz.Rect(rect.x0 - 4, rect.y0 - 4, rect.x1 + 4, rect.y1 + 4)
        text = normalize_extracted_text(page.get_text("text", clip=expanded)).strip()
    if not text:
        return ""

    text = re.sub(r"\s+", " ", text)
    if len(text) > _MAX_LABEL_CHARS:
        return ""
    if text.count(" ") > 12:
        return ""
    return text.strip(" -:")


def _infer_component_type(label: str) -> str:
    lowered = label.lower()
    if _DATA_STORE_HINT_RE.search(lowered):
        return "data_store"
    if _HUMAN_ACTOR_HINT_RE.search(lowered):
        return "human_actor"
    if _EXTERNAL_HINT_RE.search(lowered):
        return "external_entity"
    return "process"


def _extract_connector_flows(
    drawings: list[dict],
    component_geometries: dict[str, fitz.Rect],
    page_number: int,
) -> list[ParsedFlow]:
    flows: list[ParsedFlow] = []
    seen_pairs: set[tuple[str, str]] = set()
    geometry_items = list(component_geometries.items())

    for drawing in drawings:
        for item in drawing.get("items", []):
            if not item or item[0] != "l":
                continue
            start, end = item[1], item[2]
            source_name = _resolve_component_for_point(start, geometry_items)
            target_name = _resolve_component_for_point(end, geometry_items)
            if not source_name or not target_name or source_name == target_name:
                continue

            source_name, target_name = _normalize_direction(
                source_name,
                target_name,
                component_geometries,
            )
            pair_key = (source_name.lower(), target_name.lower())
            if pair_key in seen_pairs:
                continue

            seen_pairs.add(pair_key)
            flows.append(
                ParsedFlow(
                    source=source_name,
                    target=target_name,
                    label="diagram connector",
                    confidence=0.55,
                    data_types=[],
                    extraction_source="diagram",
                    evidence_page=page_number,
                    evidence_snippet=f"Connector extracted from diagram on page {page_number}.",
                )
            )

    return flows


def _resolve_component_for_point(
    point: fitz.Point,
    component_geometries: list[tuple[str, fitz.Rect]],
) -> str | None:
    for name, rect in component_geometries:
        expanded = fitz.Rect(
            rect.x0 - _LINE_TOLERANCE,
            rect.y0 - _LINE_TOLERANCE,
            rect.x1 + _LINE_TOLERANCE,
            rect.y1 + _LINE_TOLERANCE,
        )
        if expanded.contains(point):
            return name

    best_name: str | None = None
    best_distance = math.inf
    for name, rect in component_geometries:
        center_x = (rect.x0 + rect.x1) / 2
        center_y = (rect.y0 + rect.y1) / 2
        distance = math.dist((point.x, point.y), (center_x, center_y))
        if distance < best_distance and distance <= 140:
            best_distance = distance
            best_name = name
    return best_name


def _normalize_direction(
    source_name: str,
    target_name: str,
    component_geometries: dict[str, fitz.Rect],
) -> tuple[str, str]:
    source_rect = component_geometries[source_name]
    target_rect = component_geometries[target_name]
    source_center_x = (source_rect.x0 + source_rect.x1) / 2
    source_center_y = (source_rect.y0 + source_rect.y1) / 2
    target_center_x = (target_rect.x0 + target_rect.x1) / 2
    target_center_y = (target_rect.y0 + target_rect.y1) / 2
    delta_x = target_center_x - source_center_x
    delta_y = target_center_y - source_center_y

    if abs(delta_x) >= abs(delta_y):
        return (source_name, target_name) if delta_x >= 0 else (target_name, source_name)
    return (source_name, target_name) if delta_y >= 0 else (target_name, source_name)


def _extract_raster_diagram_page(
    page: fitz.Page,
    page_number: int,
) -> tuple[list[_RasterComponentCandidate], list[ParsedFlow]]:
    ocr_engine = _get_ocr_engine()
    if ocr_engine is None:
        return [], []

    image, scale = _render_page_image(page)
    ocr_results = _run_ocr(ocr_engine, image)
    if not ocr_results:
        return [], []

    binary = _build_binary_mask(image)
    candidates: list[_RasterComponentCandidate] = []
    seen_labels: set[str] = set()

    for raw_points, raw_text, raw_confidence in ocr_results:
        text = _normalize_ocr_text(raw_text)
        confidence = float(raw_confidence or 0.0)
        if confidence < _OCR_MIN_CONFIDENCE or not _is_likely_component_label(text):
            continue

        pixel_rect = _bbox_tuple_from_points(raw_points)
        if pixel_rect is None:
            continue
        if _is_duplicate_label(text, pixel_rect, candidates):
            continue

        has_container = _has_visual_component_container(binary, pixel_rect)
        if not has_container and not _COMPONENT_HINT_RE.search(text):
            continue

        page_rect = _pixel_rect_to_page_rect(pixel_rect, scale)
        normalized_label = text.lower()
        if normalized_label in seen_labels:
            continue

        seen_labels.add(normalized_label)
        candidates.append(
            _RasterComponentCandidate(
                page_rect=page_rect,
                pixel_rect=pixel_rect,
                component=ParsedComponent(
                    name=text,
                    component_type=_infer_component_type(text),
                    confidence=0.82 if has_container else 0.64,
                    description=f"Extracted from OCR on a raster diagram on page {page_number}.",
                    extraction_source="diagram_ocr",
                    evidence_page=page_number,
                    evidence_snippet=text,
                ),
            )
        )

    flows = _extract_raster_connector_flows(binary, candidates, page_number)
    return candidates, flows


def _get_ocr_engine():
    global _OCR_ENGINE, _OCR_ENGINE_READY

    if _OCR_ENGINE_READY:
        return _OCR_ENGINE
    _OCR_ENGINE_READY = True

    if RapidOCR is None:
        logger.info("rapidocr_unavailable raster diagram OCR is disabled")
        _OCR_ENGINE = None
        return None

    try:
        _OCR_ENGINE = RapidOCR()
    except Exception as exc:  # pragma: no cover - depends on optional runtime
        logger.warning("rapidocr_init_failed error=%s", exc)
        _OCR_ENGINE = None
    return _OCR_ENGINE


def _render_page_image(page: fitz.Page) -> tuple[np.ndarray, float]:
    pix = page.get_pixmap(matrix=fitz.Matrix(_RASTER_RENDER_ZOOM, _RASTER_RENDER_ZOOM), alpha=False)
    image = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)
    if pix.n > 3:
        image = image[:, :, :3]
    return image, _RASTER_RENDER_ZOOM


def _run_ocr(ocr_engine, image: np.ndarray) -> list[tuple[list[list[float]], str, float]]:
    try:
        result, _ = ocr_engine(image)
    except Exception as exc:  # pragma: no cover - runtime dependent
        logger.warning("rapidocr_run_failed error=%s", exc)
        return []
    return result or []


def _build_binary_mask(image: np.ndarray) -> np.ndarray:
    grayscale = image.mean(axis=2)
    return grayscale < 180


def _normalize_ocr_text(value: str) -> str:
    text = normalize_extracted_text(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text.strip(" -:")


def _is_likely_component_label(text: str) -> bool:
    if not text or len(text) < 3 or len(text) > _MAX_OCR_LABEL_CHARS:
        return False
    if _IGNORE_OCR_RE.match(text):
        return False
    if ":" in text and len(text.split()) > 4:
        return False
    if len(text.split()) > 7:
        return False
    alpha_count = sum(char.isalpha() for char in text)
    if alpha_count < 3:
        return False
    if _COMPONENT_HINT_RE.search(text):
        return True
    tokens = [token for token in re.split(r"\s+", text) if token]
    uppercaseish = sum(1 for token in tokens if token[:1].isupper() or token.isupper())
    return bool(tokens) and uppercaseish >= max(1, len(tokens) - 1)


def _bbox_tuple_from_points(points: list[list[float]]) -> tuple[int, int, int, int] | None:
    if not points:
        return None
    xs = [int(point[0]) for point in points]
    ys = [int(point[1]) for point in points]
    x0, x1 = min(xs), max(xs)
    y0, y1 = min(ys), max(ys)
    if x1 - x0 < 12 or y1 - y0 < 8:
        return None
    return x0, y0, x1, y1


def _pixel_rect_to_page_rect(pixel_rect: tuple[int, int, int, int], scale: float) -> fitz.Rect:
    x0, y0, x1, y1 = pixel_rect
    return fitz.Rect(x0 / scale, y0 / scale, x1 / scale, y1 / scale)


def _is_duplicate_label(
    text: str,
    pixel_rect: tuple[int, int, int, int],
    candidates: list[_RasterComponentCandidate],
) -> bool:
    lowered = text.lower()
    for candidate in candidates:
        if candidate.component.name.lower() != lowered:
            continue
        if _rect_distance(candidate.pixel_rect, pixel_rect) <= 24:
            return True
    return False


def _rect_distance(first: tuple[int, int, int, int], second: tuple[int, int, int, int]) -> float:
    first_center = ((first[0] + first[2]) / 2, (first[1] + first[3]) / 2)
    second_center = ((second[0] + second[2]) / 2, (second[1] + second[3]) / 2)
    return math.dist(first_center, second_center)


def _has_visual_component_container(binary: np.ndarray, pixel_rect: tuple[int, int, int, int]) -> bool:
    x0, y0, x1, y1 = pixel_rect
    pad_x = max(12, int((x1 - x0) * 0.22))
    pad_y = max(10, int((y1 - y0) * 0.9))

    ox0 = max(0, x0 - pad_x)
    oy0 = max(0, y0 - pad_y)
    ox1 = min(binary.shape[1], x1 + pad_x)
    oy1 = min(binary.shape[0], y1 + pad_y)
    if ox1 - ox0 < 24 or oy1 - oy0 < 18:
        return False

    top = binary[oy0: min(binary.shape[0], oy0 + 3), ox0:ox1]
    bottom = binary[max(0, oy1 - 3):oy1, ox0:ox1]
    left = binary[oy0:oy1, ox0:min(binary.shape[1], ox0 + 3)]
    right = binary[oy0:oy1, max(0, ox1 - 3):ox1]
    strips = [top, bottom, left, right]
    return all(strip.size > 0 and float(strip.mean()) >= 0.08 for strip in strips)


def _extract_raster_connector_flows(
    binary: np.ndarray,
    candidates: list[_RasterComponentCandidate],
    page_number: int,
) -> list[ParsedFlow]:
    if len(candidates) < 2:
        return []

    flows: list[ParsedFlow] = []
    seen_pairs: set[tuple[str, str]] = set()

    for first, second in itertools.combinations(candidates[:12], 2):
        if _rect_distance(first.pixel_rect, second.pixel_rect) > 900:
            continue
        oriented = _detect_connector_direction(binary, first, second, candidates)
        if oriented is None:
            continue
        source_candidate, target_candidate = oriented
        pair_key = (
            source_candidate.component.name.lower(),
            target_candidate.component.name.lower(),
        )
        if pair_key in seen_pairs:
            continue

        seen_pairs.add(pair_key)
        flows.append(
            ParsedFlow(
                source=source_candidate.component.name,
                target=target_candidate.component.name,
                label="diagram connector",
                confidence=0.58,
                data_types=[],
                extraction_source="diagram_ocr",
                evidence_page=page_number,
                evidence_snippet=(
                    f"Connector inferred from raster line between "
                    f"{source_candidate.component.name} and {target_candidate.component.name} on page {page_number}."
                ),
            )
        )

    return flows


def _detect_connector_direction(
    binary: np.ndarray,
    first: _RasterComponentCandidate,
    second: _RasterComponentCandidate,
    all_candidates: list[_RasterComponentCandidate],
) -> tuple[_RasterComponentCandidate, _RasterComponentCandidate] | None:
    ax0, ay0, ax1, ay1 = first.pixel_rect
    bx0, by0, bx1, by1 = second.pixel_rect
    a_center_x = (ax0 + ax1) / 2
    a_center_y = (ay0 + ay1) / 2
    b_center_x = (bx0 + bx1) / 2
    b_center_y = (by0 + by1) / 2
    delta_x = b_center_x - a_center_x
    delta_y = b_center_y - a_center_y

    if abs(delta_x) >= abs(delta_y):
        left, right = (first, second) if a_center_x <= b_center_x else (second, first)
        corridor = (
            left.pixel_rect[2] + 2,
            min(left.pixel_rect[1], right.pixel_rect[1]) - 40,
            right.pixel_rect[0] - 2,
            max(left.pixel_rect[3], right.pixel_rect[3]) + 40,
        )
        if corridor[2] <= corridor[0]:
            return None
        if _corridor_intersects_other_candidate(corridor, left, right, all_candidates):
            return None
        if _corridor_has_connector(binary, corridor, orientation="horizontal"):
            return left, right
        return None

    top, bottom = (first, second) if a_center_y <= b_center_y else (second, first)
    corridor = (
        min(top.pixel_rect[0], bottom.pixel_rect[0]) - 40,
        top.pixel_rect[3] + 2,
        max(top.pixel_rect[2], bottom.pixel_rect[2]) + 40,
        bottom.pixel_rect[1] - 2,
    )
    if corridor[3] <= corridor[1]:
        return None
    if _corridor_intersects_other_candidate(corridor, top, bottom, all_candidates):
        return None
    if _corridor_has_connector(binary, corridor, orientation="vertical"):
        return top, bottom
    return None


def _corridor_intersects_other_candidate(
    corridor: tuple[int, int, int, int],
    first: _RasterComponentCandidate,
    second: _RasterComponentCandidate,
    candidates: list[_RasterComponentCandidate],
) -> bool:
    cx0, cy0, cx1, cy1 = corridor
    for candidate in candidates:
        if candidate in (first, second):
            continue
        ox0, oy0, ox1, oy1 = candidate.pixel_rect
        if not (cx1 <= ox0 or cx0 >= ox1 or cy1 <= oy0 or cy0 >= oy1):
            return True
    return False


def _corridor_has_connector(
    binary: np.ndarray,
    corridor: tuple[int, int, int, int],
    *,
    orientation: str,
) -> bool:
    x0, y0, x1, y1 = corridor
    x0 = max(0, x0)
    y0 = max(0, y0)
    x1 = min(binary.shape[1], x1)
    y1 = min(binary.shape[0], y1)
    if x1 - x0 < 16 or y1 - y0 < 6:
        return False
    window = binary[y0:y1, x0:x1]
    if window.size == 0:
        return False

    if orientation == "horizontal":
        candidate_scores = [
            float(window[max(0, row - _CONNECTOR_BAND): min(window.shape[0], row + _CONNECTOR_BAND), :].mean())
            for row in range(window.shape[0])
        ]
    else:
        candidate_scores = [
            float(window[:, max(0, column - _CONNECTOR_BAND): min(window.shape[1], column + _CONNECTOR_BAND)].mean())
            for column in range(window.shape[1])
        ]
    return bool(candidate_scores) and max(candidate_scores) >= _CONNECTOR_DARK_RATIO
