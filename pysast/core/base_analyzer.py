from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class Vulnerability:
    """Класс для описания уязвимости"""
    file_path: str
    line_number: int
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    category: str
    description: str
    pattern_id: str
    language: str
    cwe_id: str
    remediation: str
    risk_score: float = 0.0
    asset_name: Optional[str] = None


class BaseAnalyzer(ABC):
    """Абстрактный базовый класс для анализаторов разных языков"""

    def __init__(self, language: str):
        self.language = language
        self.vulnerabilities: List[Vulnerability] = []

    @abstractmethod
    def analyze_file(self, file_path: str) -> List[Vulnerability]:
        """Анализ одного файла"""
        pass

    @abstractmethod
    def get_patterns(self) -> Dict[str, Any]:
        """Получить шаблоны уязвимостей для языка"""
        pass

    def calculate_risk_score(self, vulnerability: Vulnerability,
                             asset_value: float = 1.0) -> float:
        """Расчет оценки риска"""
        severity_weights = {
            'CRITICAL': 1.0,
            'HIGH': 0.8,
            'MEDIUM': 0.5,
            'LOW': 0.2
        }

        base_score = severity_weights.get(vulnerability.severity, 0.5)
        return base_score * asset_value

    def set_asset_for_vulnerability(self, vulnerability: Vulnerability,
                                    asset_name: str):
        """Установить связанный актив для уязвимости"""
        vulnerability.asset_name = asset_name