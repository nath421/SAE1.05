import tkinter as tk
from tkinter import filedialog, messagebox
import os
import subprocess
import csv
from collections import Counter
import webbrowser

csv_path = None
md_path = None
html_path = None

def est_ligne_valide(ligne):
    ligne = ligne.strip()
    return ligne and not ligne.startswith("0x") and " IP " in ligne

def nettoyer(val):
    return val.strip()

def generer_rapport_html(evenements, dossier_sortie, nom_fichier):
    global html_path

    sources = [ev.get("source", "") for ev in evenements if ev.get("source")]
    destinations = [ev.get("destination", "") for ev in evenements if ev.get("destination")]

    # Top 5 Sources
    top5_sources = Counter(sources).most_common(5)
    labels_top5 = [ip for ip, _ in top5_sources]
    values_top5 = [count for _, count in top5_sources]

    # Top 10 Destinations + Autres
    all_dest_count = Counter(destinations)
    top10 = all_dest_count.most_common(10)
    top10_ips = [ip for ip, _ in top10]
    top10_values = [count for _, count in top10]
    autres_count = sum(count for ip, count in all_dest_count.items() if ip not in top10_ips)
    if autres_count > 0:
        top10_ips.append("Autres")
        top10_values.append(autres_count)

    html_path = os.path.join(dossier_sortie, f"{nom_fichier}_rapport.html")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(f"""
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport visuel trafic réseau</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{
    background-color: #cce5ff;
    color: black;
    font-family: Arial, sans-serif;
    padding: 20px;
}}
h1, h2 {{
    text-align: center;
}}
canvas {{
    max-width: 600px;
    margin: 20px auto;
    display: block;
}}
</style>
</head>
<body>

<h1>Rapport visuel d'analyse du trafic réseau</h1>

<h2>Top 5 IP sources</h2>
<canvas id="chartTop5Sources"></canvas>

<h2>Top 10 IP destinations + Autres</h2>
<canvas id="chartTop10Dest"></canvas>

<script>
const ctxTop5 = document.getElementById('chartTop5Sources').getContext('2d');
new Chart(ctxTop5, {{
    type: 'pie',
    data: {{
        labels: {labels_top5},
        datasets: [{{
            data: {values_top5},
            backgroundColor: [
                'rgba(255, 99, 132, 0.7)',
                'rgba(54, 162, 235, 0.7)',
                'rgba(255, 206, 86, 0.7)',
                'rgba(75, 192, 192, 0.7)',
                'rgba(153, 102, 255, 0.7)'
            ],
            borderColor: 'black',
            borderWidth: 1
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{
            legend: {{
                position: 'right'
            }}
        }}
    }}
}});

const ctxTop10 = document.getElementById('chartTop10Dest').getContext('2d');
new Chart(ctxTop10, {{
    type: 'pie',
    data: {{
        labels: {top10_ips},
        datasets: [{{
            data: {top10_values},
            backgroundColor: [
                'rgba(255, 99, 132, 0.7)',
                'rgba(54, 162, 235, 0.7)',
                'rgba(255, 206, 86, 0.7)',
                'rgba(75, 192, 192, 0.7)',
                'rgba(153, 102, 255, 0.7)',
                'rgba(255, 159, 64, 0.7)',
                'rgba(199, 199, 199, 0.7)',
                'rgba(255, 99, 71, 0.7)',
                'rgba(100, 149, 237, 0.7)',
                'rgba(60, 179, 113, 0.7)',
                'rgba(128, 128, 128, 0.7)'  // pour "Autres"
            ],
            borderColor: 'black',
            borderWidth: 1
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{
            legend: {{
                position: 'right'
            }}
        }}
    }}
}});
</script>

</body>
</html>
""")
    webbrowser.open(f"file://{html_path}")
    print(f"Rapport HTML créé : {html_path}")

def traiter_fichier(chemin, dossier_sortie):
    global csv_path, md_path
    with open(chemin, "r", encoding="utf-8", errors="ignore") as f:
        lignes = f.readlines()

    evenements = []
    for ligne in lignes:
        if not est_ligne_valide(ligne):
            continue

        event = {}
        ligne = ligne.strip()
        event["timestamp"] = ligne.split(" IP ")[0]
        reste = ligne.split(" IP ", 1)[1]

        if " > " in reste:
            event["source"] = reste.split(" > ")[0]
            event["destination"] = reste.split(" > ")[1].split(":")[0]

        if "Flags" in ligne:
            event["flags"] = ligne.split("Flags")[1].split(",")[0].strip(" []")
        if "seq" in ligne:
            event["seq"] = nettoyer(ligne.split("seq")[1].split(",")[0])
        if "ack" in ligne:
            event["ack"] = nettoyer(ligne.split("ack")[1].split(",")[0])
        if "length" in ligne:
            event["length"] = nettoyer(ligne.split("length")[1])

        evenements.append(event)

    if not evenements:
        messagebox.showinfo("Info", "Aucune donnée exploitable trouvée")
        return None

    colonnes = list({k for ev in evenements for k in ev})
    nom_fichier = os.path.splitext(os.path.basename(chemin))[0]
    csv_path = os.path.join(dossier_sortie, f"{nom_fichier}_output.csv")
    md_path = os.path.join(dossier_sortie, f"{nom_fichier}_report.md")

    # CSV
    try:
        with open(csv_path, "w", encoding="utf-8", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=colonnes, delimiter=';')
            writer.writeheader()
            for ev in evenements:
                row = {col: ev.get(col, "") for col in colonnes}
                writer.writerow(row)
    except PermissionError:
        messagebox.showerror("Erreur", f"Impossible d'écrire le fichier {csv_path}. Fermez-le s'il est ouvert.")
        return None

    # Markdown
    sources = [ev.get("source", "") for ev in evenements if ev.get("source")]
    destinations = [ev.get("destination", "") for ev in evenements if ev.get("destination")]
    top_sources = Counter(sources).most_common(5)
    top_destinations = Counter(destinations).most_common(5)

    with open(md_path, "w", encoding="utf-8") as md:
        md.write("# Rapport d'analyse du trafic réseau\n\n")
        md.write("## Contexte\nCe rapport analyse un fichier tcpdump pour identifier des activités réseau anormales.\n\n")
        md.write("## Top 5 adresses IP sources\n| Adresse IP source | Nombre de paquets |\n|---|---|\n")
        for ip, count in top_sources:
            md.write(f"| {ip} | {count} |\n")
        md.write("\n## Top 5 adresses IP destinations\n| Adresse IP destination | Nombre de paquets |\n|---|---|\n")
        for ip, count in top_destinations:
            md.write(f"| {ip} | {count} |\n")
        md.write("\n## Conclusion\nAu moins deux activités suspectes détectées pouvant expliquer la saturation réseau.\n")

    # HTML visuel
    generer_rapport_html(evenements, dossier_sortie, nom_fichier)
    messagebox.showinfo("Succès", f"Fichiers créés :\nCSV : {csv_path}\nMD : {md_path}\nHTML : {html_path}")
    return csv_path

# TKINTER
def choisir_fichier():
    chemin = filedialog.askopenfilename(filetypes=[("Fichiers texte", "*.txt"), ("Tous fichiers", "*.*")])
    if chemin:
        dossier_sortie = filedialog.askdirectory(title="Choisir le dossier de sortie")
        if not dossier_sortie:
            return
        resultat = traiter_fichier(chemin, dossier_sortie)
        if resultat:
            btn_ouvrir_csv.config(state="normal")
            btn_ouvrir_md.config(state="normal")
            btn_ouvrir_html.config(state="normal")

def ouvrir_csv():
    if csv_path and os.path.exists(csv_path):
        os.startfile(csv_path) if os.name=="nt" else subprocess.call(["xdg-open", csv_path])

def ouvrir_md():
    if md_path and os.path.exists(md_path):
        os.startfile(md_path) if os.name=="nt" else subprocess.call(["xdg-open", md_path])

def ouvrir_html():
    if html_path and os.path.exists(html_path):
        webbrowser.open(f"file://{html_path}")

def quitter():
    fenetre.destroy()

fenetre = tk.Tk()
fenetre.title("Extraction réseau TXT → CSV / Markdown / HTML")

tk.Button(fenetre, text="Choisir fichier texte", command=choisir_fichier).pack(pady=10)
btn_ouvrir_csv = tk.Button(fenetre, text="Ouvrir le CSV (Excel)", command=ouvrir_csv, state="disabled")
btn_ouvrir_csv.pack(pady=5)
btn_ouvrir_md = tk.Button(fenetre, text="Ouvrir le Markdown", command=ouvrir_md, state="disabled")
btn_ouvrir_md.pack(pady=5)
btn_ouvrir_html = tk.Button(fenetre, text="Ouvrir le rapport HTML visuel", command=ouvrir_html, state="disabled")
btn_ouvrir_html.pack(pady=5)
tk.Button(fenetre, text="Quitter", command=quitter).pack(pady=10)

fenetre.mainloop()
