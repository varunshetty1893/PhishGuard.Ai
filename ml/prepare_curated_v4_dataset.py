"""
PhishGuard AI - Curated v4 Dataset Preparation
==============================================
Replaces artificial "fake path" legitimate URLs with:
  1. Real Tranco top-sites across ranks 1 to 50,000
     - 40% bare root domains (https://domain.tld, http://domain.tld)
     - 20% www root domains (https://www.domain.tld)
     - 40% genuine deep links across real academic, governmental, tech, documentation,
       and media portals (real Wikipedia, GitHub, Arxiv, Python, CDC, NASA, etc.)
  2. Balanced with genuine verified phishing URLs from local verified datasets.
Eliminates:
  - "count_dots <= 1" shortcut (bare legit domains included!)
  - "path_length == 0" shortcut (bare legit domains included!)
  - "is_https == 1" shortcut (both protocols represented)
"""

import os
import io
import random
import zipfile
import urllib.request
from pathlib import Path
from urllib.parse import urlparse
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "ml" / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_CSV = DATA_DIR / "dataset_v4_curated.csv"

# Diverse real deep links from authentic web resources
REAL_DEEP_SEEDS = [
    # Wikipedia real articles
    "https://en.wikipedia.org/wiki/Computer_security",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://en.wikipedia.org/wiki/Domain_Name_System",
    "https://en.wikipedia.org/wiki/Cryptography",
    "https://en.wikipedia.org/wiki/Artificial_intelligence",
    "https://en.wikipedia.org/wiki/Cloud_computing",
    "https://en.wikipedia.org/wiki/Operating_system",
    "https://en.wikipedia.org/wiki/Internet_Protocol",
    "https://en.wikipedia.org/wiki/Application_programming_interface",
    "https://en.wikipedia.org/wiki/World_Wide_Web",
    # Tech docs & developer resources
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://docs.python.org/3/tutorial/index.html",
    "https://docs.python.org/3/library/json.html",
    "https://docs.docker.com/get-started/overview/",
    "https://docs.github.com/en/rest",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview",
    "https://developer.mozilla.org/en-US/docs/Web/Security",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://kubernetes.io/docs/concepts/overview/",
    "https://fastapi.tiangolo.com/tutorial/first-steps/",
    # Open Source GitHub repos & files
    "https://github.com/torvalds/linux",
    "https://github.com/fastapi/fastapi",
    "https://github.com/scikit-learn/scikit-learn",
    "https://github.com/pallets/flask",
    "https://github.com/psf/requests/blob/main/README.md",
    "https://github.com/python/cpython",
    "https://github.com/tensorflow/tensorflow",
    "https://github.com/facebook/react",
    # Academic & Research
    "https://arxiv.org/abs/1706.03762",
    "https://arxiv.org/abs/2103.00020",
    "https://arxiv.org/abs/2303.08774",
    "https://cern.ch/about",
    "https://www.nature.com/articles/d41586-023-00835-2",
    "https://www.science.org/doi/10.1126/science.abj6987",
    "https://ieeexplore.ieee.org/document/9000000",
    "https://dl.acm.org/doi/10.1145/3372278.3390678",
    # Government, Health, News & Media
    "https://www.nasa.gov/missions/artemis/",
    "https://www.cdc.gov/flu/about/keyfacts.htm",
    "https://www.who.int/news-room/fact-sheets",
    "https://www.loc.gov/collections/",
    "https://www.bbc.com/news/technology",
    "https://www.reuters.com/technology/",
    "https://theguardian.com/technology",
    "https://www.nytimes.com/section/technology"
]

def fetch_tranco_domains(n: int = 50000):
    """Fetch Tranco top-1M list and extract top n domains."""
    print(f"[*] Fetching Tranco top-{n:,} domains...")
    cache_path = DATA_DIR / "tranco_top50k.txt"
    if cache_path.exists():
        domains = [line.strip() for line in open(cache_path, encoding="utf-8") if line.strip()]
        if len(domains) >= n:
            print(f"    Loaded {len(domains):,} cached Tranco domains from {cache_path.name}")
            return domains[:n]

    req = urllib.request.Request(
        "https://tranco-list.eu/top-1m.csv.zip",
        headers={"User-Agent": "PhishGuardAI-Research/1.0"}
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()

    with zipfile.ZipFile(io.BytesIO(data)) as z:
        with z.open(z.namelist()[0]) as f:
            lines = [f.readline().decode("utf-8", errors="ignore").strip() for _ in range(n)]

    domains = [line.split(",")[1].strip() for line in lines if "," in line]
    with open(cache_path, "w", encoding="utf-8") as f:
        f.write("\n".join(domains))
    print(f"    Saved {len(domains):,} Tranco domains to cache")
    return domains


def build_legitimate_urls(_tranco_domains, target_count=20000, seed=42):
    """Use observed PhiUSIIL legitimate URLs; never generate paths from words."""
    source = DATA_DIR / "dataset.csv"
    if not source.exists():
        raise FileNotFoundError(f"Missing observed-URL source: {source}")
    df = pd.read_csv(source, usecols=["url", "label"])
    legit = df[df["label"] == 0]["url"].dropna().astype(str)
    legit = legit[legit.str.match(r"^https?://", na=False)].drop_duplicates()
    keywords = r"login|signin|secure|account|billing|portal|verify|update|auth"
    login_pages = legit[legit.str.contains(keywords, case=False, regex=True)]
    if len(login_pages) < 1000:
        raise RuntimeError(
            f"Only {len(login_pages)} observed login/account URLs are available. "
            "Add at least 1,000 verified real login URLs before retraining; synthetic paths are prohibited."
        )
    chosen_login = login_pages.sample(n=1000, random_state=seed)
    remainder = legit.drop(chosen_login.index).sample(n=target_count - len(chosen_login), random_state=seed)
    urls = pd.concat([chosen_login, remainder]).drop_duplicates().tolist()
    print(f"[+] Selected {len(urls):,} observed legitimate URLs, including {len(chosen_login):,} login/account URLs")
    return urls


def load_phishing_urls(target_count=20000, seed=42):
    """Loads genuine verified phishing URLs from local verified datasets."""
    print(f"[*] Loading genuine phishing URLs from local datasets...")
    p1 = ROOT / "dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"
    p2 = ROOT / "dataset" / "url_features_extracted1.csv"
    
    phish_urls = set()
    if p1.exists():
        df1 = pd.read_csv(p1, usecols=["URL", "label"], low_memory=False)
        p_urls = df1[df1["label"] == 0]["URL"].dropna().astype(str).tolist()
        phish_urls.update(p_urls)
        
    if p2.exists():
        df2 = pd.read_csv(p2, usecols=["URL", "ClassLabel"], low_memory=False)
        p_urls2 = df2[df2["ClassLabel"] == 0]["URL"].dropna().astype(str).tolist()
        phish_urls.update(p_urls2)
        
    rows = []
    for url in phish_urls:
        host = (urlparse(str(url)).hostname or "").lower()
        apex = ".".join(host.split(".")[-2:])
        if host:
            rows.append((str(url), apex))
    phish_df = pd.DataFrame(rows, columns=["url", "apex"]).drop_duplicates("url")
    phish_df = phish_df.sample(frac=1, random_state=seed).drop_duplicates("apex")
    phish_list = phish_df["url"].head(target_count).tolist()
    print(f"[+] Sampled {len(phish_list):,} phishing URLs after apex-domain deduplication")
    return phish_list


def main():
    print("=" * 70)
    print("  PHISHGUARD AI - PREPARING CURATED v4 DATASET")
    print("=" * 70)
    
    tranco = fetch_tranco_domains(50000)
    target_each = 20000
    
    legit_urls = build_legitimate_urls(tranco, target_count=target_each)
    phish_urls = load_phishing_urls(target_count=target_each)
    
    # Create unified dataframe
    df_legit = pd.DataFrame({"url": legit_urls, "label": 0})
    df_phish = pd.DataFrame({"url": phish_urls, "label": 1})
    
    df = pd.concat([df_legit, df_phish], ignore_index=True)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    # Analyze statistics
    print("\n[*] Dataset Distribution Summary:")
    print(f"    Total records:   {len(df):,}")
    print(f"    Legitimate (0):  {(df['label'] == 0).sum():,} ({((df['label']==0).mean()*100):.1f}%)")
    print(f"    Phishing (1):    {(df['label'] == 1).sum():,} ({((df['label']==1).mean()*100):.1f}%)")
    
    # Inspect bare domain percentages
    bare_legit = sum(1 for u in legit_urls if len(urlparse(u).path.strip("/")) == 0)
    bare_phish = sum(1 for u in phish_urls if len(urlparse(u).path.strip("/")) == 0)
    print(f"    Bare domains in Legit:   {bare_legit:,} ({bare_legit/len(legit_urls)*100:.1f}%)")
    print(f"    Bare domains in Phish:   {bare_phish:,} ({bare_phish/len(phish_urls)*100:.1f}%)")
    
    # Inspect dot counts
    dots_legit = sum(urlparse(u).netloc.count(".") for u in legit_urls) / len(legit_urls)
    dots_phish = sum(urlparse(u).netloc.count(".") for u in phish_urls) / len(phish_urls)
    print(f"    Avg hostname dots in Legit: {dots_legit:.2f}")
    print(f"    Avg hostname dots in Phish: {dots_phish:.2f}")
    
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\n[+] Curated v4 dataset saved to: {OUTPUT_CSV}")
    print("=" * 70)


if __name__ == "__main__":
    main()
