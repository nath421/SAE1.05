import tkinter as tk
from tkinter import filedialog
import os
import subprocess
from datetime import datetime

def format_datetime(dt_str):
    """
    Convertit une date ICS (YYYYMMDDTHHMMSS ou YYYYMMDDTHHMM) en format lisible : JJ/MM/AAAA HH:MM
    Supprime les fuseaux horaires et le 'Z' de fin si présent.
    """
    # Supprime tout avant le ':' si fuseau TZID
    if ':' in dt_str:
        dt_str = dt_str.split(':', 1)[-1]

    # Supprime le 'Z' final (UTC)
    dt_str = dt_str.rstrip('Z')

    # Gestion date avec ou sans secondes
    try:
        dt = datetime.strptime(dt_str, "%Y%m%dT%H%M%S")
    except ValueError:
        dt = datetime.strptime(dt_str, "%Y%m%dT%H%M")
    return dt.strftime("%d/%m/%Y %H:%M")

def traiter_fichier_ics(chemin):
    """
    Lit un fichier ICS pour plusieurs événements et crée un CSV.
    Ne garde que la dernière ligne non vide de DESCRIPTION.
    Convertit les dates en format lisible.
    """
    with open(chemin, 'r', encoding='utf-8') as f:
        lignes = f.readlines()

    evenements = []
    evenement = {}
    for ligne in lignes:
        ligne = ligne.strip()
        if ligne == "BEGIN:VEVENT":
            evenement = {}
        elif ligne.startswith("SUMMARY:"):
            evenement['Summary'] = ligne[len("SUMMARY:"):]
        elif ligne.startswith("DTSTART"):
            # Gère DTSTART ou DTSTART;TZID=...
            evenement['Start'] = format_datetime(ligne.split(":", 1)[1])
        elif ligne.startswith("DTEND"):
            evenement['End'] = format_datetime(ligne.split(":", 1)[1])
        elif ligne.startswith("LOCATION:"):
            evenement['Location'] = ligne[len("LOCATION:"):]
        elif ligne.startswith("DESCRIPTION:"):
            desc = ligne[len("DESCRIPTION:"):].split("\\n")
            lignes_non_vides = [l.strip() for l in desc if l.strip()]
            evenement['Description'] = lignes_non_vides[-1] if lignes_non_vides else ""
        elif ligne == "END:VEVENT":
            evenements.append(evenement)

    # Entêtes et valeurs CSV
    entetes = ["Summary", "Start", "End", "Location", "Description"]
    nom_csv = chemin.replace(".ics", ".csv")

    with open(nom_csv, 'w', encoding='utf-8') as f:
        f.write(";".join(entetes) + "\n")
        for ev in evenements:
            f.write(";".join([ev.get(h, "") for h in entetes]) + "\n")

    label_chemin.config(text=f"CSV créé : {nom_csv}")
    btn_ouvrir_csv.config(state="normal")
    print(f"CSV créé : {nom_csv}")

def choisir_fichier():
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier ICS",
        filetypes=[("Fichiers ICS", "*.ics")]
    )
    if chemin_fichier:
        label_chemin.config(text=f"Fichier sélectionné : {chemin_fichier}")
        traiter_fichier_ics(chemin_fichier)
    else:
        label_chemin.config(text="Aucun fichier sélectionné")

def ouvrir_csv():
    chemin_csv = label_chemin.cget("text").replace("CSV créé : ", "")
    if os.path.exists(chemin_csv):
        if os.name == "nt":  # Windows
            os.startfile(chemin_csv)
        elif os.name == "posix":  # Mac ou Linux
            subprocess.call(["open" if os.uname().sysname == "Darwin" else "xdg-open", chemin_csv])

def quitter():
    fenetre.destroy()

# --- Interface Tkinter ---
fenetre = tk.Tk()
fenetre.title("ICS → CSV")
fenetre.geometry("500x250")

btn_choisir_fichier = tk.Button(fenetre, text="Choisir un fichier ICS", command=choisir_fichier)
btn_choisir_fichier.pack(pady=10)

label_chemin = tk.Label(fenetre, text="Aucun fichier sélectionné")
label_chemin.pack(pady=10)

btn_ouvrir_csv = tk.Button(fenetre, text="Ouvrir le CSV", command=ouvrir_csv, state="disabled")
btn_ouvrir_csv.pack(pady=10)

btn_quitter = tk.Button(fenetre, text="Quitter", command=quitter)
btn_quitter.pack(pady=10)

fenetre.mainloop()
