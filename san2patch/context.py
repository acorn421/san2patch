from san2patch.patching.context.code_context import ContextManager
from san2patch.utils.enum import CODE_CONTEXT_MODE, TEMPERATURE_SETTING
from san2patch.utils.logger import BaseLogger


def singleton(cls):
    _instances = {}

    def get_instance(*args, force_new_instance=False, **kwargs):
        if force_new_instance or cls not in _instances:
            _instances[cls] = cls(*args, **kwargs)
        return _instances[cls]

    return get_instance


@singleton
class San2PatchTemperatureManager:
    ZERO = 0
    MEDIUM = 0.5
    HIGH = 1.0
    PEAK = 1.5
    temperatures = {
        "zero": (0, 0, 0),
        "low": (0.2, 0.5, 0.7),
        "medium": (0.5, 0.8, 1.0),
        "high": (0.8, 1.0, 1.3),
        "zero_zero": (ZERO, ZERO, ZERO),
        "zero_medium": (ZERO, MEDIUM, MEDIUM),
        "zero_high": (ZERO, HIGH, HIGH),
        "zero_peak": (ZERO, PEAK, PEAK),
        "medium_zero": (MEDIUM, ZERO, ZERO),
        "medium_medium": (MEDIUM, MEDIUM, MEDIUM),
        "medium_high": (MEDIUM, HIGH, HIGH),
        "medium_peak": (MEDIUM, PEAK, PEAK),
        "high_zero": (HIGH, ZERO, ZERO),
        "high_medium": (HIGH, MEDIUM, MEDIUM),
        "high_high": (HIGH, HIGH, HIGH),
        "high_peak": (HIGH, PEAK, PEAK),
        "peak_zero": (PEAK, ZERO, ZERO),
        "peak_medium": (PEAK, MEDIUM, MEDIUM),
        "peak_high": (PEAK, HIGH, HIGH),
        "peak_peak": (PEAK, PEAK, PEAK),
    }

    def __init__(self, temperature_setting: TEMPERATURE_SETTING = "medium"):
        self.default, self.genpatch, self.branch = self.temperatures[
            temperature_setting
        ]


@singleton
class San2PatchValidatorManager:
    def __init__(self, docker_id: str | None = None):
        self.docker_id = docker_id


@singleton
class San2PatchContextManager(ContextManager):
    def __init__(self, src_dir: str, context_mode: CODE_CONTEXT_MODE = "ast"):
        super().__init__(language="C", src_dir=src_dir, context_mode=context_mode)


@singleton
class San2PatchLogger(BaseLogger):
    def __init__(
        self,
        vuln_id: str = "  SAN2PATCH  ",
        log_level: int | None = None,
        file_handler: bool = False,
    ):
        super().__init__(vuln_id, log_level, file_handler)


def init_context(
    vuln_id: str,
    src_dir: str,
    context_mode: CODE_CONTEXT_MODE = "ast",
    temperature_setting: TEMPERATURE_SETTING = "medium",
    docker_id: str | None = None,
    log_level: int | None = None,
    file_handler: bool = False,
):
    San2PatchLogger(
        vuln_id,
        log_level,
        file_handler,
        force_new_instance=True,
    )

    San2PatchContextManager(
        src_dir,
        context_mode,
        force_new_instance=True,
    )

    San2PatchTemperatureManager(
        temperature_setting,
        force_new_instance=True,
    )

    San2PatchValidatorManager(
        docker_id,
        force_new_instance=True,
    )
