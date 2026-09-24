"""
Main entry point for the USSO server application.

This module initializes and runs the FastAPI server with graceful shutdown handling.
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path

import uvicorn

from server.config import Settings
from server.server import app

__all__ = ["app"]


async def main() -> None:
    """
    Initialize and run the USSO server with graceful shutdown.

    Sets up signal handlers for SIGINT and SIGTERM to enable graceful shutdown.
    The server runs on 0.0.0.0:8000 with a single worker.
    """
    module = Path(__file__).stem
    config = uvicorn.Config(
        f"{module}:app",
        host="0.0.0.0",  # ruff:ignore[hardcoded-bind-all-interfaces]
        port=8000,
        access_log=True,
        workers=1,
        log_config=Settings.get_log_config(),
    )
    server = uvicorn.Server(config)

    # Setup graceful shutdown
    loop = asyncio.get_running_loop()

    stop_event = asyncio.Event()

    def shutdown(sig: int) -> None:
        """
        Handle shutdown signal.

        Args:
            sig: The signal number that triggered the shutdown.

        """
        logging.info("Received stop signal %d. Initiating graceful shutdown...", sig)
        stop_event.set()
        server.handle_exit(sig=sig, frame=None)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown, sig)

    # Start server in background
    server_task = asyncio.create_task(server.serve())

    # Wait for signal
    await stop_event.wait()

    # Now gracefully shutdown server
    logging.info("Shutdown complete.")

    # Optional: wait for server task to finish if needed
    server_task.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception:
        logging.exception("Unexpected exception occurred")
        sys.exit(1)
