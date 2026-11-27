"""Regenerate the readable catalog and example scripts from the same GUI recipes."""
from pathlib import Path

from nft_gui.templates import preview_template
from nft_gui.templates.catalog import REFERENCES, TEMPLATES


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    examples = root / "examples" / "templates"
    docs = root / "docs"
    examples.mkdir(parents=True, exist_ok=True)
    docs.mkdir(exist_ok=True)
    lines = ["# Modèles nftables expliqués", "",
             "Ce catalogue est généré depuis les mêmes modèles que l’interface. Les valeurs proposées sont des exemples à adapter. Les scripts remplacent le ruleset complet ; ils ne sont pas appliqués par cet export.", "",
             "## Lire une règle", "",
             "| Élément | Rôle |", "| --- | --- |",
             "| `input` | Paquets destinés à cette machine. |",
             "| `output` | Paquets émis par cette machine. |",
             "| `forward` | Paquets qui traversent le routeur. |",
             "| `iifname` / `oifname` | Interfaces d’entrée / de sortie. |",
             "| `ip saddr` / `ip daddr` | Adresse ou réseau source / destination IPv4. |",
             "| `tcp dport` / `udp dport` | Port du service visé. |",
             "| `ct state` | État de l’échange selon le suivi de connexion. |",
             "| `counter` | Compteur de paquets et d’octets, sans décision de filtrage. |",
             "| `accept` / `drop` | Autoriser dans cette chaîne / abandonner le paquet. |",
             "| `policy drop` | Abandonner ce qui atteint la fin de la chaîne. |",
             "| `dnat` / `snat` / `masquerade` | Traduire les adresses, indépendamment des autorisations de transfert. |", "",
             "Les critères d’une même règle se cumulent. L’ordre est significatif à l’intérieur de chaque chaîne. `log` et `counter` ne terminent pas l’évaluation. Une autorisation dans une chaîne ne contourne pas les autres chaînes du système.", "",
             "## Sources", ""]
    for ref in REFERENCES:
        lines += [f"- **{ref.title}** — {ref.location}", f"  {ref.note}"]
    lines += ["", "## Catalogue", ""]
    for template in TEMPLATES:
        p = preview_template(template.id)
        (examples / f"{template.id}.nft").write_text(str(p["source"]), encoding="utf-8")
        lines += [f"### {template.title}", "", f"Catégorie : {template.category}. Origine : {template.origin}.", "", template.summary, "",
                  f"Script complet : [examples/templates/{template.id}.nft](../examples/templates/{template.id}.nft)", "",
                  "Paramètres proposés :", "", "| Paramètre | Exemple | Précision |", "| --- | --- | --- |"]
        for param in template.parameters:
            lines.append(f"| {param.label} | `{param.default}` | {param.help} |")
        lines += ["", "Prérequis :", "", *[f"- {s}" for s in template.prerequisites], "", "Portée et limites :", "", *[f"- {s}" for s in template.caveats], "",
                  "Règles dans leur ordre au sein de chaque chaîne :", ""]
        for excerpt in template.excerpts:
            lines += ["**Extrait original de la formation**", "", "```nft", excerpt.code, "```", "", excerpt.explanation, "", "Adaptation : " + excerpt.adaptation, ""]
        for rule in p["rules"]:
            lines += [f"**{rule['table']} / {rule['chain']} · {rule['order']} — {rule['title']}**", "", "```nft", str(rule["code"]), "```", "", str(rule["explanation"]), ""]
    (docs / "modeles-expliques.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"{len(TEMPLATES)} modèles exportés dans {examples}")


if __name__ == "__main__":
    main()
