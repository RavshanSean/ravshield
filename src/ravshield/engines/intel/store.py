from ravshield.intel.ioc import IOC


class IOCStore:
    def __init__(self) -> None:
        self._items: dict[tuple[str, str], IOC] = {}

    def add(self, ioc: IOC) -> None:
        key = (ioc.indicator_type.lower(), ioc.value.strip().lower())
        self._items[key] = ioc

    def get(self, indicator_type: str, value: str) -> IOC | None:
        key = (indicator_type.lower(), value.strip().lower())
        return self._items.get(key)

    def contains(self, indicator_type: str, value: str) -> bool:
        return self.get(indicator_type, value) is not None