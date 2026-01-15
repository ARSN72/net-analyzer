import json
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from app.db.database import Base


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_ip = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String, nullable=True)
    scan_data = Column(Text, nullable=False)  # JSON string of full scan result

    @staticmethod
    def serialize_scan_data(scan_result: dict) -> str:
        return json.dumps(scan_result, default=str)
