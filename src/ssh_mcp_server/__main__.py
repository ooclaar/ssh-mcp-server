"""Permite execução com: python -m ssh_mcp_server"""

from .server import main
import asyncio

if __name__ == "__main__":
    asyncio.run(main())
