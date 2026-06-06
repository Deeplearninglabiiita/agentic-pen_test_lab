from typing import TypedDict, Annotated, List, Optional
import operator

class Target(TypedDict):
    ip: str
    hostname: Optional[str]
    ports: List[int]
    services: dict
    vulnerabilities: List[str]
    priority: int

class Credential(TypedDict):
    username: str
    password: Optional[str]
    hash: Optional[str]
    source: str
    target: str

class PentestState(TypedDict):
    scope: List[str]
    objectives: List[str]
    targets: Annotated[List[Target], operator.add]
    current_target: Optional[Target]
    credentials: Annotated[List[Credential], operator.add]
    shells: List[str]
    messages: Annotated[List, operator.add]
    phase: str
    iteration: int
    max_iterations: int
    findings: Annotated[List[str], operator.add]
    errors: Annotated[List[str], operator.add]
