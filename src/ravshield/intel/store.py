from collections.abc import Iterator

from ravshield.intel.ioc import (
    IOC,
    normalize_indicator_type,
    normalize_indicator_value,
)


class IOCStore:
    """
    In-memory IOC intelligence store.

    A persistent database adapter can replace this implementation
    later without changing the public matching interface.
    """

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], IOC] = {}

    @staticmethod
    def _build_key(
        indicator_type: str,
        value: str,
    ) -> tuple[str, str]:
        normalized_type = normalize_indicator_type(
            indicator_type
        )
        normalized_value = normalize_indicator_value(
            normalized_type,
            value,
        )

        return normalized_type, normalized_value

    def add(self, ioc: IOC) -> None:
        key = self._build_key(
            ioc.indicator_type,
            ioc.value,
        )

        self._items[key] = ioc

    def get(
        self,
        indicator_type: str,
        value: str,
    ) -> IOC | None:
        try:
            key = self._build_key(
                indicator_type,
                value,
            )
        except ValueError:
            return None

        return self._items.get(key)

    def contains(
        self,
        indicator_type: str,
        value: str,
    ) -> bool:
        return self.get(indicator_type, value) is not None

    def remove(
        self,
        indicator_type: str,
        value: str,
    ) -> bool:
        try:
            key = self._build_key(
                indicator_type,
                value,
            )
        except ValueError:
            return False

        return self._items.pop(key, None) is not None

    def clear(self) -> None:
        self._items.clear()

    def all(self) -> list[IOC]:
        return list(self._items.values())

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[IOC]:
        return iter(self._items.values())