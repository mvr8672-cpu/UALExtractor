from pathlib import Path

from ualextractor.inspector.finder import UFEDFinder


def main() -> None:
    print("UALExtractor v0.1")
    print("-----------------")

    folder = input("UFED hoofdmap: ").strip()

    finder = UFEDFinder()

    db = finder.find_db(Path(folder))

    if db is None:
        print("Geen geldige UFED db-map gevonden.")
        return

    print(f"DB gevonden: {db}")


if __name__ == "__main__":
    main()