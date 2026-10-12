from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    scenario_runtime_endpoint: str = Field(
        default="127.0.0.1:50051",
        validation_alias="SCENARIO_RUNTIME_ENDPOINT",
        min_length=1,
    )
    scenario_runtime_token: SecretStr = Field(
        validation_alias="SCENARIO_RUNTIME_TOKEN",
        min_length=1,
    )
    scenario_runtime_verify_tls: bool = Field(
        default=True,
        validation_alias="SCENARIO_RUNTIME_VERIFY_TLS",
    )
    scenario_runtime_arena: str | None = Field(
        default=None,
        validation_alias="SCENARIO_RUNTIME_ARENA",
        min_length=1,
        max_length=64,
    )
    remote_run_label: str = Field(
        default="bluesec1-agent",
        validation_alias="REMOTE_RUN_LABEL",
        min_length=1,
    )
    agent_name: str = Field(
        default="bluesec1-agent",
        validation_alias="AGENT_NAME",
        min_length=1,
        max_length=255,
    )

    llm_base_url: str = Field(validation_alias="LLM_BASE_URL", min_length=1)
    llm_api_key: SecretStr = Field(validation_alias="LLM_API_KEY", min_length=1)
    llm_default_model: str = Field(validation_alias="LLM_DEFAULT_MODEL", min_length=1)
    llm_timeout_seconds: float = Field(
        default=120.0,
        validation_alias="LLM_TIMEOUT_SECONDS",
        gt=0,
    )
    llm_max_completion_tokens: int = Field(
        default=16_384,
        validation_alias="LLM_MAX_COMPLETION_TOKENS",
        gt=0,
    )
    llm_max_step_retries: int = Field(
        default=3,
        validation_alias="LLM_MAX_STEP_RETRIES",
        ge=1,
        le=5,
    )
    agent_max_steps: int = Field(
        default=100,
        validation_alias="BLUESEC_AGENT_MAX_STEPS",
        ge=1,
        le=100,
    )
    agent_max_tasks: int | None = Field(
        default=None,
        validation_alias="BLUESEC_AGENT_MAX_TASKS",
        ge=1,
    )
    llm_simplify_tool_schemas: bool = Field(
        default=False,
        validation_alias="LLM_SIMPLIFY_TOOL_SCHEMAS",
    )
    agent_total_cap: int | None = Field(
        default=None,
        validation_alias="BLUESEC_AGENT_TOTAL_CAP",
        ge=3,
    )
    agent_type_budgets: bool = Field(
        default=False,
        validation_alias="BLUESEC_AGENT_TYPE_BUDGETS",
    )
    agent_deadline_minutes: float | None = Field(
        default=None,
        validation_alias="BLUESEC_AGENT_DEADLINE_MINUTES",
        gt=0,
    )
    agent_harvest_calls: int = Field(
        default=1,
        validation_alias="BLUESEC_AGENT_HARVEST_CALLS",
        ge=0,
        le=20,
    )
    agent_scenario_notes: bool = Field(
        default=True,
        validation_alias="BLUESEC_AGENT_SCENARIO_NOTES",
    )
    agent_complete_report_share: float | None = Field(
        default=None,
        validation_alias="BLUESEC_AGENT_COMPLETE_REPORT_SHARE",
        ge=0,
        le=1,
    )
    agent_empty_benign_review: bool = Field(
        default=False,
        validation_alias="BLUESEC_AGENT_EMPTY_BENIGN_REVIEW",
    )
    agent_artifact_sweep: bool = Field(
        default=False,
        validation_alias="BLUESEC_AGENT_ARTIFACT_SWEEP",
    )
    agent_keep_going: bool = Field(
        default=False,
        validation_alias="BLUESEC_AGENT_KEEP_GOING",
    )
    agent_simulate_hidden: str | None = Field(
        default=None,
        validation_alias="BLUESEC_AGENT_SIMULATE_HIDDEN",
    )
    agent_log_dir: str | None = Field(
        default="runs",
        validation_alias="AGENT_LOG_DIR",
    )
