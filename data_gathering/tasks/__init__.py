"""Task discovery helpers for data gathering."""

from __future__ import annotations

import pkgutil
from importlib import import_module
from typing import Iterable


def task_modules() -> list[str]:
    package_name = __name__
    modules: list[str] = []
    for module in pkgutil.iter_modules(__path__):
        if module.ispkg:
            modules.append(f"{package_name}.{module.name}.tasks")
    return modules


def collect_task_names() -> list[str]:
    names: list[str] = []
    for module_path in task_modules():
        module = import_module(module_path)
        task_names = getattr(module, "TASK_NAMES", [])
        for name in task_names:
            if name not in names:
                names.append(name)
    return names


def filter_tasks(all_tasks: Iterable[str], allow_list: str | None) -> list[str]:
    if not allow_list:
        return list(all_tasks)
    allowed = {item.strip() for item in allow_list.split(",") if item.strip()}
    return [name for name in all_tasks if name in allowed]
