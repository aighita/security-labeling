import pandas as pd
import matplotlib.pyplot as plt
from dotenv import dotenv_values
import requests
import time

# === Config ===
GITHUB_TOKEN = dotenv_values('.env')['GIT_HUB_TOKEN']
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"}
INPUT_FILE = 'package-analysis_agl-demo-platform_raspberrypi4-64.xlsx'
OUTPUT_FILE = 'rezultate_eticheta_securitate.xlsx'
SHEET_NAME = 'package-analysis_agl-demo-platf'

# === 1. Load Data ===
df = pd.read_excel(INPUT_FILE, sheet_name=SHEET_NAME)

# === 2. Normalize [0–10] ===
columns_to_normalize = [
    'CVE Analysis Safety', 'Static Code Analysis Status',
    'Dynamic Program Analysis Status', 'Code Coverage'
]

for col in columns_to_normalize:
    min_val = df[col].min()
    max_val = df[col].max()
    df[f'{col} (Norm)'] = df[col].apply(
        lambda x: round((x - min_val) / (max_val - min_val) * 10, 2) if max_val > min_val else 0
    )

# === 3. GitHub API Search Function ===
def search_repo(query):
    url = f"https://api.github.com/search/repositories?q={query}+in:name,description&per_page=5"
    response = requests.get(url, headers=HEADERS)
    status = response.status_code

    if status != 200:
        print(f"[ERROR] '{query}' → HTTP {status}")
        return {
            "repo_name": None,
            "repo_url": None,
            "stars": None,
            "last_updated": None
        }

    items = response.json().get("items", [])
    if not items:
        print(f"[NOT FOUND] '{query}' → No repositories found.")
        return {
            "repo_name": None,
            "repo_url": None,
            "stars": None,
            "last_updated": None
        }

    # Cuvinte cheie relevante pentru embedded/RPi
    keywords = ['raspberry', 'yocto', 'openembedded', 'meta', 'agl', 'embedded', 'linux']

    # Cautăm cel mai potrivit
    for item in items:
        desc = (item.get("description") or "").lower()
        name = (item.get("name") or "").lower()
        if any(keyword in desc or keyword in name for keyword in keywords):
            print(f"[MATCHED] '{query}' → {item['full_name']} (⭐ {item['stargazers_count']})")
            return {
                "repo_name": item["full_name"],
                "repo_url": item["html_url"],
                "stars": item["stargazers_count"],
                "last_updated": item["updated_at"]
            }

    # Dacă nu s-a găsit nimic relevant, returnăm primul
    top_result = items[0]
    print(f"[FALLBACK] '{query}' → {top_result['full_name']} (⭐ {top_result['stargazers_count']}) [no keyword match]")
    return {
        "repo_name": top_result["full_name"],
        "repo_url": top_result["html_url"],
        "stars": top_result["stargazers_count"],
        "last_updated": top_result["updated_at"]
    }

# === 4. GitHub Search & Criticality Estimation ===
results = []
search_cache = {}
search_success = 0
search_fail = 0

for name in df['Package Name']:
    base_name = name.split('-')[0]

    if base_name in search_cache:
        info = search_cache[base_name].copy()
        info['package'] = name
        results.append(info)
        continue

    print(f">> Searching GitHub for: {base_name}")
    info = search_repo(base_name)

    stars = info['stars']
    if stars is None:
        criticitate = 6.0
        search_fail += 1
    elif stars > 10000:
        criticitate = 10
        search_success += 1
    elif stars > 5000:
        criticitate = 9
        search_success += 1
    elif stars > 1000:
        criticitate = 8
        search_success += 1
    elif stars > 500:
        criticitate = 7
        search_success += 1
    elif stars > 100:
        criticitate = 6
        search_success += 1
    else:
        criticitate = 5
        search_success += 1

    info['criticitate_estimata'] = criticitate
    info['package'] = name

    search_cache[base_name] = info.copy()
    results.append(info)

    time.sleep(1)

github_df = pd.DataFrame(results)

# === 5. Merge Results with Original ===
df = df.merge(github_df[['package', 'criticitate_estimata', 'stars']], 
              left_on='Package Name', right_on='package', how='left')
df['Criticitate'] = df['criticitate_estimata'].fillna(6.0)

# === 6. Final Security Score Calculation ===
df['Scor Securitate'] = (
    0.30 * df['Criticitate'] +
    0.25 * df['CVE Analysis Safety (Norm)'] +
    0.15 * df['Static Code Analysis Status (Norm)'] +
    0.15 * df['Dynamic Program Analysis Status (Norm)'] +
    0.15 * df['Code Coverage (Norm)']
).round(2)

# === 7. Platform-level Aggregated Scores ===
global_score_mean = round(df['Scor Securitate'].mean(), 2)
global_score_crit_only = round(df[df['Criticitate'] >= 8.0]['Scor Securitate'].mean(), 2)
global_score_min = round(df['Scor Securitate'].min(), 2)
global_score_max = round(df['Scor Securitate'].max(), 2)

summary = pd.DataFrame({
    'Tip Agregare': [
        'Scor general platformă (medie)',
        'Media pachetelor critice (C ≥ 8)',
        'Scor minim (cel mai slab pachet)',
        'Scor maxim (cel mai sigur pachet)'
    ],
    'Scor Agregat': [
        global_score_mean,
        global_score_crit_only,
        global_score_min,
        global_score_max
    ]
})

# === 8. GitHub Statistics Summary ===
total_searches = len(search_cache)
num_found = search_success
num_failed = search_fail
max_stars = github_df['stars'].max()
min_stars = github_df['stars'].min()
most_starred_repo = github_df.loc[github_df['stars'].idxmax()] if not github_df['stars'].isnull().all() else None
least_starred_repo = github_df.loc[github_df['stars'].idxmin()] if not github_df['stars'].isnull().all() else None

stats_data = {
    'Metrică': [
        'Număr total pachete unice căutate',
        'Căutări GitHub reușite',
        'Căutări GitHub eșuate',
        'Repo cu cele mai multe stele',
        'Repo cu cele mai puține stele',
        'Nr. stele maxim',
        'Nr. stele minim'
    ],
    'Valoare': [
        total_searches,
        num_found,
        num_failed,
        most_starred_repo["repo_name"] if most_starred_repo is not None else "N/A",
        least_starred_repo["repo_name"] if least_starred_repo is not None else "N/A",
        max_stars,
        min_stars
    ]
}

# === 8.1 Scriere fișier pentru criticality_score ===
repo_list = github_df['repo_name'].dropna().unique()
with open('criticality_input.yml', 'w') as f:
    f.write("repos:\n")
    for repo in repo_list:
        f.write(f"  - repo: \"{repo}\"\n")

print(">> Fișier YAML pentru criticality_score generat: criticality_input.yml")
print(">> Rulează manual în terminal:")

import subprocess

# === 8.1.1 Rulează criticality_score dacă tool-ul este disponibil ===
criticality_output_file = 'criticality_output.csv'

try:
    print(">> Rulăm criticality_score automat...")
    subprocess.run([
        'python3', '-m', 'criticality_score.run',
        '--input=criticality_input.yml',
        f'--github_token={GITHUB_TOKEN}',
        '--output_format=csv',
        f'--output={criticality_output_file}'
    ], check=True)
    print(f">> Scoruri scrise în {criticality_output_file}")
except Exception as e:
    print(f">> [ERROR] Eroare la rularea criticality_score: {e}")

# === 8.2 Injectare scoruri reale criticality_score ===
try:
    crit_df = pd.read_csv('criticality_output.csv')
    crit_df['repo'] = crit_df['repo'].str.lower()

    # Creează mapare: repo → scor real (normalizat 0–10)
    crit_df['criticality_score_norm'] = (crit_df['criticality_score'] * 10).round(2)
    repo_to_score = dict(zip(crit_df['repo'], crit_df['criticality_score_norm']))

    # Adaugă scor real în github_df
    github_df['repo_lower'] = github_df['repo_name'].str.lower()
    github_df['criticitate_ossf'] = github_df['repo_lower'].map(repo_to_score)

    # Actualizează scor criticitate în df principal dacă există scor real
    df = df.merge(github_df[['package', 'criticitate_ossf']], left_on='Package Name', right_on='package', how='left')
    df['Criticitate'] = df['criticitate_ossf'].fillna(df['Criticitate'])

    print(">> Scoruri realiste de criticitate din criticality_score injectate cu succes.")
except FileNotFoundError:
    print(">> [WARN] Nu s-a găsit criticality_output.csv — folosim scorurile estimate din stele.")


gh_stats = pd.DataFrame(stats_data)

# === 9. Grafic distribuție scoruri ===
plt.figure(figsize=(10, 6))
plt.hist(df['Scor Securitate'], bins=20, color='skyblue', edgecolor='black')
plt.axvline(global_score_mean, color='red', linestyle='dashed', linewidth=2, label=f'Media totală: {global_score_mean}')
plt.axvline(global_score_crit_only, color='green', linestyle='dotted', linewidth=2, label=f'Media critice: {global_score_crit_only}')
plt.axvline(global_score_min, color='orange', linestyle='dashdot', linewidth=2, label=f'Minim: {global_score_min}')
plt.title('Distribuția scorurilor de securitate pe pachet')
plt.xlabel('Scor Securitate')
plt.ylabel('Număr Pachete')
plt.legend()
plt.tight_layout()
plt.savefig('distributie_scoruri_securitate.png')

# === 10. Export Excel ===
with pd.ExcelWriter(OUTPUT_FILE) as writer:
    df.to_excel(writer, sheet_name='Scoruri Detaliate', index=False)
    summary.to_excel(writer, sheet_name='Agregari Platforma', index=False)
    gh_stats.to_excel(writer, sheet_name='Statistici GitHub', index=False)

# === 11. Final Log ===
print(">> Totul a fost procesat cu succes.")
print(f">> Fișier salvat: {OUTPUT_FILE}")
print(">> Grafic: distributie_scoruri_securitate.png")
