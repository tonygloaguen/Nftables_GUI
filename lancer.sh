#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$project_dir"
python_bin=/usr/bin/python3
if [[ ! -x "$python_bin" ]]; then
    python_bin="$(command -v python3)"
fi
"$python_bin" -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11 ou supérieur est requis"'
if [[ ! -x "$project_dir/.venv/bin/python" ]]; then
    printf '%s\n' 'Création de l’environnement Python du projet…'
    "$python_bin" -m venv "$project_dir/.venv"
fi
venv_python="$project_dir/.venv/bin/python"
if ! "$venv_python" -c 'import fastapi, uvicorn; from pydantic import model_validator' 2>/dev/null; then
    printf '%s\n' 'Installation des dépendances déclarées dans pyproject.toml…'
    "$venv_python" -m pip install -e "$project_dir"
fi
printf '%s\n' 'Démarrage de Nftables GUI. Par défaut : http://127.0.0.1:8420' 'Ctrl+C pour arrêter le serveur.'
exec "$venv_python" -m nft_gui
