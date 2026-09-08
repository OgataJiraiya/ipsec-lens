import json
from pathlib import Path
from sqlalchemy import create_engine, String, Text, Integer, select, update, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from backend.schemas.models import Analysis


class Base(DeclarativeBase):
    pass


class Run(Base):
    __tablename__ = "analysis_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[str] = mapped_column(String(40), index=True)
    capture_sha256: Mapped[str] = mapped_column(String(64), index=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    document: Mapped[str] = mapped_column(Text)


class Store:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.engine = create_engine(f"sqlite:///{directory / 'analyses.db'}", connect_args={"check_same_thread": False})
        @event.listens_for(self.engine, "connect")
        def configure(connection, _):
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA busy_timeout=5000")
        Base.metadata.create_all(self.engine)

    def save(self, result: Analysis):
        with Session(self.engine) as session, session.begin():
            session.add(Run(id=result.analysis_id, created_at=result.created_at, capture_sha256=result.capture_sha256,
                            revision=result.revision, document=result.model_dump_json()))

    def get(self, identity: str) -> Analysis | None:
        with Session(self.engine) as session:
            row = session.get(Run, identity)
            return Analysis.model_validate_json(row.document) if row else None

    def list(self, limit=50, offset=0):
        with Session(self.engine) as session:
            rows = session.scalars(select(Run).order_by(Run.created_at.desc()).limit(limit).offset(offset))
            return [{k: v for k, v in json.loads(row.document).items()
                     if k in ("analysis_id", "created_at", "label", "capture_filename", "packet_count", "policy", "score")}
                    for row in rows]

    def replace(self, result: Analysis, expected_revision: int):
        with Session(self.engine) as session, session.begin():
            changed = session.execute(update(Run).where(Run.id == result.analysis_id, Run.revision == expected_revision)
                .values(document=result.model_dump_json(), revision=result.revision))
            if getattr(changed, "rowcount", 0) != 1:
                raise ValueError("Analysis changed concurrently; reload and retry")
