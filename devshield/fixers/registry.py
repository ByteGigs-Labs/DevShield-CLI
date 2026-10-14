from __future__ import annotations

from devshield.fixers.base import Fixer
from devshield.fixers.ci import StarterWorkflow, WorkflowPermissions
from devshield.fixers.docker import CreateDockerignore, NonRootUser
from devshield.fixers.env import DisableDebug, EnvExample
from devshield.fixers.gitignore import IgnoreEnvFiles

# Order matters: fixers run in sequence on one shared workspace.
FIXERS: tuple[type[Fixer], ...] = (
    IgnoreEnvFiles,
    DisableDebug,
    EnvExample,
    CreateDockerignore,
    NonRootUser,
    WorkflowPermissions,
    StarterWorkflow,
)
FIXABLE_RULES = frozenset(fixer.rule_id for fixer in FIXERS)
