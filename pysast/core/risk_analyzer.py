from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from .base_analyzer import Vulnerability


@dataclass
class Asset:
    """Класс для описания актива"""
    name: str
    description: str
    criticality: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidentiality: int  # 1-3
    integrity: int  # 1-3
    availability: int  # 1-3
    business_value: float  # 1.0-10.0


@dataclass
class RiskAssessment:
    """Оценка риска"""
    vulnerability: Vulnerability
    asset: Asset
    probability: float  # 0.0-1.0
    impact: float  # 0.0-1.0
    risk_score: float  # probability * impact * asset.business_value
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL


class RiskAnalyzer:
    """Анализатор рисков безопасности"""

    def __init__(self):
        self.assets = self._load_default_assets()
        self.threat_matrix = self._load_threat_matrix()

    def _load_default_assets(self) -> List[Asset]:
        """Загрузка каталога активов по умолчанию"""
        return [
            Asset(
                name="Исходный код",
                description="Исходный код проектов компании",
                criticality="HIGH",
                confidentiality=3,
                integrity=3,
                availability=3,
                business_value=9.0
            ),
            Asset(
                name="База данных клиентов",
                description="Персональные данные и история заказов",
                criticality="HIGH",
                confidentiality=3,
                integrity=3,
                availability=2,
                business_value=8.5
            ),
            Asset(
                name="Финансовые документы",
                description="Счета, акты, зарплатные ведомости",
                criticality="HIGH",
                confidentiality=3,
                integrity=3,
                availability=2,
                business_value=8.0
            ),
            Asset(
                name="Конфигурационные файлы",
                description="Настройки приложений и сервисов",
                criticality="MEDIUM",
                confidentiality=2,
                integrity=3,
                availability=2,
                business_value=6.0
            ),
            Asset(
                name="Логи приложений",
                description="Журналы событий и ошибок",
                criticality="LOW",
                confidentiality=1,
                integrity=2,
                availability=2,
                business_value=4.0
            )
        ]

    def _load_threat_matrix(self) -> Dict[str, Dict[str, Any]]:
        """Матрица угроз и их вероятностей"""
        return {
            # Python уязвимости
            'PYTHON-SQLI-001': {'probability': 0.7, 'impact': 0.8, 'asset': 'База данных клиентов'},
            'PYTHON-CMD-001': {'probability': 0.4, 'impact': 0.9, 'asset': 'Исходный код'},
            'PYTHON-DES-001': {'probability': 0.3, 'impact': 0.95, 'asset': 'Исходный код'},
            'PYTHON-FI-001': {'probability': 0.5, 'impact': 0.7, 'asset': 'Конфигурационные файлы'},

            # Java уязвимости
            'JAVA-SQLI-001': {'probability': 0.6, 'impact': 0.8, 'asset': 'База данных клиентов'},
            'JAVA-DES-001': {'probability': 0.3, 'impact': 0.9, 'asset': 'Исходный код'},
            'JAVA-PT-001': {'probability': 0.4, 'impact': 0.6, 'asset': 'Конфигурационные файлы'},

            # PHP уязвимости
            'PHP-SQLI-001': {'probability': 0.8, 'impact': 0.8, 'asset': 'База данных клиентов'},
            'PHP-FI-001': {'probability': 0.6, 'impact': 0.7, 'asset': 'Исходный код'},
            'PHP-CMD-001': {'probability': 0.5, 'impact': 0.9, 'asset': 'Исходный код'},
            'PHP-XSS-001': {'probability': 0.7, 'impact': 0.5, 'asset': 'Исходный код'},

            # Общие уязвимости
            'SQLI-001': {'probability': 0.7, 'impact': 0.8, 'asset': 'База данных клиентов'},
            'CMD-001': {'probability': 0.5, 'impact': 0.9, 'asset': 'Исходный код'},
            'DES-001': {'probability': 0.4, 'impact': 0.9, 'asset': 'Исходный код'},
            'XSS-001': {'probability': 0.6, 'impact': 0.5, 'asset': 'Исходный код'},
            'FI-001': {'probability': 0.5, 'impact': 0.7, 'asset': 'Конфигурационные файлы'}
        }

    def assess_risk(self, vulnerability: Vulnerability,
                    asset_name: str = None) -> RiskAssessment:
        """Оценка риска для конкретной уязвимости"""

        # Определение актива
        if asset_name:
            asset = self._find_asset_by_name(asset_name)
        else:
            asset = self._determine_asset(vulnerability)

        if not asset:
            asset = self.assets[0]  # Актив по умолчанию

        # Получение вероятности и воздействия из матрицы угроз
        threat_info = self.threat_matrix.get(
            vulnerability.pattern_id,
            {'probability': 0.5, 'impact': 0.5, 'asset': asset.name}
        )

        # Расчет оценки риска
        probability = threat_info['probability']
        impact = threat_info['impact']

        # Корректировка на основе серьезности уязвимости
        severity_factor = {
            'CRITICAL': 1.0,
            'HIGH': 0.8,
            'MEDIUM': 0.5,
            'LOW': 0.2
        }.get(vulnerability.severity, 0.5)

        impact *= severity_factor

        # Корректировка на основе критичности актива
        criticality_factor = {
            'CRITICAL': 1.2,
            'HIGH': 1.0,
            'MEDIUM': 0.7,
            'LOW': 0.4
        }.get(asset.criticality, 0.5)

        risk_score = probability * impact * asset.business_value * criticality_factor

        # Определение уровня риска
        if risk_score >= 6.0:
            risk_level = "CRITICAL"
        elif risk_score >= 4.0:
            risk_level = "HIGH"
        elif risk_score >= 2.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return RiskAssessment(
            vulnerability=vulnerability,
            asset=asset,
            probability=probability,
            impact=impact,
            risk_score=risk_score,
            risk_level=risk_level
        )

    def _find_asset_by_name(self, asset_name: str) -> Optional[Asset]:
        """Поиск актива по имени"""
        for asset in self.assets:
            if asset.name.lower() == asset_name.lower():
                return asset
        return None

    def _determine_asset(self, vulnerability: Vulnerability) -> Asset:
        """Эвристическое определение актива по уязвимости"""
        file_path = vulnerability.file_path.lower()

        # Определяем по категории уязвимости
        if vulnerability.category in ['INJECTION', 'SQL_INJECTION']:
            for asset in self.assets:
                if 'база данных' in asset.name.lower() or 'database' in asset.name.lower():
                    return asset

        # Определяем по пути файла
        if any(keyword in file_path for keyword in ['database', 'db/', 'sql', 'model']):
            return self._find_asset_by_name('База данных клиентов')
        elif any(keyword in file_path for keyword in ['finance', 'account', 'бухгалтер']):
            return self._find_asset_by_name('Финансовые документы')
        elif any(keyword in file_path for keyword in ['config', 'settings', 'env']):
            return self._find_asset_by_name('Конфигурационные файлы')
        elif any(keyword in file_path for keyword in ['log', 'журнал', 'logger']):
            return self._find_asset_by_name('Логи приложений')
        else:
            return self._find_asset_by_name('Исходный код')

    def generate_risk_report(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Генерация отчета по рискам"""
        risk_assessments = []
        total_risk_score = 0.0
        risk_by_asset = {}
        risk_by_category = {}

        for vuln in vulnerabilities:
            assessment = self.assess_risk(vuln)
            risk_assessments.append(assessment)
            total_risk_score += assessment.risk_score

            # Группировка по активам
            asset_name = assessment.asset.name
            if asset_name not in risk_by_asset:
                risk_by_asset[asset_name] = []
            risk_by_asset[asset_name].append(assessment)

            # Группировка по категориям
            category = vuln.category
            if category not in risk_by_category:
                risk_by_category[category] = []
            risk_by_category[category].append(assessment)

        # Статистика по уровням риска
        risk_levels = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for assessment in risk_assessments:
            risk_levels[assessment.risk_level] += 1

        # Топ-5 самых рисковых уязвимостей
        top_risks = sorted(risk_assessments, key=lambda x: x.risk_score, reverse=True)[:5]

        return {
            'total_risks': len(risk_assessments),
            'total_risk_score': total_risk_score,
            'average_risk_score': total_risk_score / len(risk_assessments) if risk_assessments else 0,
            'risk_levels': risk_levels,
            'risk_by_asset': {asset: len(assessments) for asset, assessments in risk_by_asset.items()},
            'risk_by_category': {category: len(assessments) for category, assessments in risk_by_category.items()},
            'top_risks': [
                {
                    'file': a.vulnerability.file_path,
                    'line': a.vulnerability.line_number,
                    'vulnerability': a.vulnerability.description,
                    'asset': a.asset.name,
                    'probability': round(a.probability, 2),
                    'impact': round(a.impact, 2),
                    'risk_score': round(a.risk_score, 2),
                    'risk_level': a.risk_level
                }
                for a in top_risks
            ],
            'assessments': [
                {
                    'file': a.vulnerability.file_path,
                    'line': a.vulnerability.line_number,
                    'vulnerability': a.vulnerability.description,
                    'severity': a.vulnerability.severity,
                    'category': a.vulnerability.category,
                    'asset': a.asset.name,
                    'probability': round(a.probability, 2),
                    'impact': round(a.impact, 2),
                    'risk_score': round(a.risk_score, 2),
                    'risk_level': a.risk_level
                }
                for a in risk_assessments
            ]
        }

    def get_assets(self) -> List[Asset]:
        """Получить список всех активов"""
        return self.assets

    def add_asset(self, asset: Asset):
        """Добавить новый актив"""
        self.assets.append(asset)