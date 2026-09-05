import os
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.db.session import Base
from app.models.models import Repository, Scan, Report
from app.agents.supervisor import SupervisorAgent

@pytest.mark.asyncio
async def test_full_e2e_scan_pipeline():
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    TestSessionLocal = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)

    async with TestSessionLocal() as session:
        demo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../demo_repo"))
        
        # 1. Create Repository
        repo = Repository(
            name="Test E2E Demo Repo",
            storage_path=demo_dir,
            is_demo=True
        )
        session.add(repo)
        await session.commit()
        await session.refresh(repo)

        # 2. Create Scan
        scan = Scan(
            repository_id=repo.id,
            status="QUEUED"
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        # 3. Run Supervisor Agent Pipeline
        supervisor = SupervisorAgent(session)
        await supervisor.run_scan_pipeline(scan.id)

        # 4. Verify Scan Results
        await session.refresh(scan)
        assert scan.status == "COMPLETED"
        assert scan.progress == 100.0
        assert scan.total_vulnerabilities > 0
        assert scan.critical_count > 0
        assert scan.security_score < 100.0  # Penalties applied correctly
        assert scan.duration_seconds > 0.0

        # 5. Verify Report and PDF Generation
        report_stmt = select(Report).where(Report.scan_id == scan.id)
        report_res = await session.execute(report_stmt)
        report = report_res.scalar_one_or_none()
        assert report is not None
        assert report.title is not None
        assert report.pdf_path is not None
        assert os.path.exists(report.pdf_path)

    await test_engine.dispose()
