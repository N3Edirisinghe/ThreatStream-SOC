import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

async def main():
    db_url = "postgresql+asyncpg://soc_app:changeme123@localhost:5432/soc_db"
    engine = create_async_engine(db_url)
    
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE users SET password_hash = :hash WHERE username = 'admin'"),
            {"hash": "$2b$12$XHGFCjN2I1cwz73BLnJopeFBr26QQKtpEgUKPX3ncftZVcunN1KEm"}
        )
        print("Updated admin password successfully")

asyncio.run(main())
