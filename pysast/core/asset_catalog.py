from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass
class Asset:
    """Класс для описания актива (дублируется для совместимости)"""
    name: str
    description: str
    criticality: str
    confidentiality: int
    integrity: int
    availability: int
    business_value: float


class AssetCatalog:
    """Каталог активов для анализа рисков"""

    def __init__(self):
        self.assets = self._load_default_assets()

    def _load_default_assets(self) -> List[Asset]:
        """Загрузка активов по умолчанию из лабораторной работы"""
        return [
            Asset(
                name="Исходный код текущих проектов",
                description="Основной продукт компании, результат интеллектуального труда",
                criticality="HIGH",
                confidentiality=3,
                integrity=3,
                availability=3,
                business_value=9.0
            ),
            Asset(
                name="База данных клиентов",
                description="Персональные данные, история заказов, коммерческие предложения",
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
                name="Репутация компании",
                description="Нематериальный актив, формирующий доверие клиентов",
                criticality="MEDIUM",
                confidentiality=1,
                integrity=2,
                availability=3,
                business_value=7.0
            ),
            Asset(
                name="Конфигурация серверов",
                description="Настройки серверов, сетевого оборудования",
                criticality="MEDIUM",
                confidentiality=2,
                integrity=3,
                availability=2,
                business_value=6.5
            ),
            Asset(
                name="Резервные копии",
                description="Архивные копии данных для восстановления",
                criticality="MEDIUM",
                confidentiality=3,
                integrity=3,
                availability=1,
                business_value=6.0
            )
        ]

    def find_asset_by_name(self, name: str) -> Asset:
        """Найти актив по имени"""
        for asset in self.assets:
            if asset.name.lower() == name.lower():
                return asset
        # Возвращаем актив по умолчанию
        return self.assets[0]

    def get_assets_by_criticality(self, criticality: str) -> List[Asset]:
        """Получить активы по критичности"""
        return [asset for asset in self.assets if asset.criticality == criticality]

    def calculate_total_business_value(self) -> float:
        """Рассчитать общую бизнес-ценность активов"""
        return sum(asset.business_value for asset in self.assets)

    def get_assets_summary(self) -> Dict[str, Any]:
        """Получить сводку по активам"""
        return {
            'total_assets': len(self.assets),
            'critical_assets': len(self.get_assets_by_criticality('CRITICAL')),
            'high_assets': len(self.get_assets_by_criticality('HIGH')),
            'medium_assets': len(self.get_assets_by_criticality('MEDIUM')),
            'low_assets': len(self.get_assets_by_criticality('LOW')),
            'total_business_value': self.calculate_total_business_value()
        }