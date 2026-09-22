import json
import os
import re
import stat
from pathlib import Path
from sqlalchemy import create_engine, String, Text, Integer, select, update, delete, event
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
        self.directory = directory.resolve()
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

    def delete(self, identity: str) -> bool:
        """Serialize with writers; unlink only the generated capture before DB commit.

        Unlink failure rolls back the row deletion. A commit failure/crash after unlink
        can leave an analysis with a missing capture; retry safely completes deletion.
        Never recurse, resolve a capture link, or accept a path from the document.
        """
        if not re.fullmatch(r"[0-9a-f]{32}", identity):
            raise ValueError("Invalid analysis identity")
        with Session(self.engine) as session, session.begin():
            document = session.scalar(delete(Run).where(Run.id == identity).returning(Run.document))
            if document is None:
                return False
            analysis = Analysis.model_validate_json(document)
            if analysis.retain_capture:
                self._remove_capture(identity)
        return True

    def _remove_capture(self, identity: str):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        root = os.open(self.directory, flags)
        try:
            try:
                captures = os.open("captures", flags, dir_fd=root)
            except FileNotFoundError:
                return
            try:
                name = identity + ".pcap"
                try:
                    info = os.stat(name, dir_fd=captures, follow_symlinks=False)
                except FileNotFoundError:
                    return
                if not stat.S_ISREG(info.st_mode):
                    raise OSError("Retained capture is not a regular file")
                # unlinkat never follows a final symlink, even if replaced after stat.
                os.unlink(name, dir_fd=captures)
            finally:
                os.close(captures)
        finally:
            os.close(root)
