"""
Correlator: links FilterToConsumerBindings with their EventFilters and
EventConsumers, and identifies orphaned artefacts.

Matching is done on normalised (lower-case, stripped) names.  When the carver
produces multiple candidates for the same name, the one with higher confidence
is kept.  Orphans (filters or consumers without a binding) are reported
separately as residual artefacts from past or incomplete installations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .carver import CarverResult
from .models import EventConsumer, EventFilter, FilterToConsumerBinding, WMIPersistenceBundle

logger = logging.getLogger(__name__)


@dataclass
class CorrelationResult:
    bundles: list[WMIPersistenceBundle]  = field(default_factory=list)
    orphaned_filters: list[EventFilter]  = field(default_factory=list)
    orphaned_consumers: list[EventConsumer] = field(default_factory=list)


class WMICorrelator:
    def __init__(self, carver_result: CarverResult) -> None:
        self._result = carver_result

        self._filters = _best_by_confidence(
            carver_result.filters, key=lambda f: f.name.lower().strip()
        )
        self._consumers = _best_by_confidence(
            carver_result.consumers,
            key=lambda c: (c.consumer_type.lower().strip(), c.name.lower().strip()),
        )
        self._consumers_by_name = _best_by_confidence(
            carver_result.consumers, key=lambda c: c.name.lower().strip()
        )

    def correlate(self) -> CorrelationResult:
        result = CorrelationResult()
        matched_filters:   set[str]          = set()
        matched_consumers: set[tuple[str, str]] = set()

        for binding in self._result.bindings:
            bundle = self._resolve_binding(binding)
            result.bundles.append(bundle)
            if bundle.event_filter:
                matched_filters.add(bundle.event_filter.name.lower().strip())
            if bundle.consumer:
                matched_consumers.add(
                    (bundle.consumer.consumer_type.lower(), bundle.consumer.name.lower())
                )

        for name, flt in self._filters.items():
            if name not in matched_filters:
                result.orphaned_filters.append(flt)

        for key, consumer in self._consumers.items():
            if key not in matched_consumers:
                result.orphaned_consumers.append(consumer)

        logger.info(
            "Correlation: %d bundles, %d orphaned filters, %d orphaned consumers",
            len(result.bundles), len(result.orphaned_filters), len(result.orphaned_consumers),
        )
        return result

    def _resolve_binding(self, binding: FilterToConsumerBinding) -> WMIPersistenceBundle:
        filter_key     = binding.filter_name.lower().strip()
        consumer_key   = (binding.consumer_type.lower().strip(), binding.consumer_name.lower().strip())
        consumer_key_n = binding.consumer_name.lower().strip()

        resolved_filter   = self._filters.get(filter_key)
        resolved_consumer = self._consumers.get(consumer_key) or self._consumers_by_name.get(consumer_key_n)

        is_orphaned  = resolved_filter is None or resolved_consumer is None
        is_incomplete = resolved_filter is None or resolved_consumer is None

        if resolved_filter is None:
            logger.debug("Binding %s: filter '%s' not found", binding.consumer_name, binding.filter_name)
        if resolved_consumer is None:
            logger.debug("Binding %s: consumer '%s' not found", binding.consumer_name, binding.consumer_name)

        return WMIPersistenceBundle(
            binding=binding,
            event_filter=resolved_filter,
            consumer=resolved_consumer,
            is_orphaned=is_orphaned,
            is_incomplete=is_incomplete,
        )


def _best_by_confidence(items: list, key) -> dict:
    """Keep the highest-confidence item per key when duplicates exist."""
    result: dict = {}
    for item in items:
        k = key(item)
        if k not in result or item.confidence > result[k].confidence:
            result[k] = item
    return result
