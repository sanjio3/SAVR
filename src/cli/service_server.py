import uvicorn
import os


def main() -> int:
    host = os.environ.get("SAST_AI_API_HOST", "127.0.0.1")
    port = int(os.environ.get("SAST_AI_API_PORT", "8000"))
    uvicorn.run("src.api.app:app", host=host, port=port, reload=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
