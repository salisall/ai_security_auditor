from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from datetime import datetime

class ThreatType(Enum):
    """Enumeration of security threat types - all 12 from the image"""
    # Prompt Injection / Tampering / Bloating / Blocking (4 types)
    PROMPT_INJECTION = "prompt_injection"
    PROMPT_TAMPERING = "prompt_tampering"
    PROMPT_BLOATING = "prompt_bloating"
    PROMPT_BLOCKING = "prompt_blocking"
    #Minh

    # Malicious / Offensive / Phishing / Spam Content (4 types)
    MALICIOUS_CONTENT = "malicious_content"
    OFFENSIVE_CONTENT = "offensive_content"
    PHISHING_CONTENT = "phishing_content"
    SPAM_CONTENT = "spam_content"
    #Quan

    # Malicious Code Generation (1 type)
    MALICIOUS_CODE_GENERATION = "malicious_code_generation"
    # Detection Evasion Text (1 type)
    DETECTION_EVASION_TEXT = "detection_evasion_text"
    # Intensive Prompt Attack (1 type)
    INTENSIVE_PROMPT_ATTACK = "intensive_prompt_attack"
    #Kean
    
    # Response Blocking (Safety/Availability) (2 types)
    RESPONSE_BLOCKING_SAFETY = "response_blocking_safety"
    RESPONSE_BLOCKING_AVAILABILITY = "response_blocking_availability"
    #Steven

class RiskLevel(Enum):
    """Risk severity levels"""
    
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EXTREME = 5

class AttackVector(Enum):
    """Attack vector categories"""
    INPUT_MANIPULATION = "input_manipulation"
    TRAINING_TIME = "training_time"
    INFERENCE_TIME = "inference_time"
    MODEL_WEIGHTS = "model_weights"
    TRAINING_DATA = "training_data"

@dataclass
class ThreatVector:
    """Represents a specific security threat vector"""
    id: str
    name: str
    threat_type: ThreatType
    attack_vector: AttackVector
    description: str
    attack_examples: List[str]
    mitigation_strategies: List[str]
    risk_level: RiskLevel
    cve_references: List[str] = None
    academic_references: List[str] = None
    real_world_incidents: List[str] = None
    
    def __post_init__(self):
        if self.cve_references is None:
            self.cve_references = []
        if self.academic_references is None:
            self.academic_references = []
        if self.real_world_incidents is None:
            self.real_world_incidents = []
