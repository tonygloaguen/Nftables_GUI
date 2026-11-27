from __future__ import annotations

from nft_gui.config import Settings


def main() -> None:
    import uvicorn
    from nft_gui.api import create_app

    settings = Settings.from_env()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port,
                workers=1, proxy_headers=False)


if __name__ == "__main__":
    main()
