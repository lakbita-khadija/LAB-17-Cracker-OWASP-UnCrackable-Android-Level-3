# LAB 17 — Cracker OWASP UnCrackable Android Level 3
**Cours : Sécurité des Applications Mobiles**  

---

##  Objectifs d'apprentissage

À la fin de ce lab, vous saurez :
- Décompiler et patcher une APK (smali + Java)
- Analyser une librairie native (`.so`) avec Ghidra
- Contourner l'anti-debug, l'anti-Frida, l'anti-root et la vérification d'intégrité CRC
- Comprendre un XOR byte-by-byte et calculer le mot de passe secret
- Utiliser uniquement des outils **gratuits** (Android Studio + Ghidra + apktool + Jadx)

---

##  Prérequis et Setup

### Environnement utilisé
| Composant | Détail |
|-----------|--------|
| OS principal | Kali Linux (VM VMware) |
| Émulateur Android | Android Studio (Windows host) |
| Architecture émulateur | x86_64 |
| Connexion Kali ↔ Windows | Réseau VMware (192.168.59.x) |

### Outils à installer

#### Sur Kali Linux
```bash
# apktool
sudo apt update && sudo apt install -y apktool
apktool --version  # v2.7.0

# Jadx-GUI
sudo apt install -y jadx
jadx-gui &

# Ghidra
sudo apt install -y ghidra
ghidra &

# adb
sudo apt install -y adb
```

#### Sur Windows (host)
- Android Studio avec un émulateur AVD **x86_64, API 30+**
- `adb` disponible dans le PATH

### Télécharger l'APK
```bash
# Fix DNS si nécessaire
echo "185.199.108.133 raw.githubusercontent.com" | sudo tee -a /etc/hosts

# Télécharger
cd ~/Desktop
wget https://raw.githubusercontent.com/OWASP/mastg/master/Crackmes/Android/Level_03/UnCrackable-Level3.apk
<img width="942" height="341" alt="image" src="https://github.com/user-attachments/assets/522aa9ae-0532-4c05-af7f-71eb9c8517c6" />

# Installer sur l'émulateur (depuis Windows)
adb -s emulator-5556 install UnCrackable-Level3.apk
```

> **Résultat** : L'app s'ouvre et affiche un popup "Root/Tampering detected" → normal, c'est ce qu'on va contourner.

---

## Vue d'ensemble des protections

L'application implémente **4 niveaux de protection** :

| Protection | Localisation | Méthode de contournement |
|------------|-------------|--------------------------|
| Détection root | `MainActivity.onCreate()` smali | Patch smali → `return-void` |
| Vérification CRC | `verifyLibs()` smali | Vider la méthode |
| Anti-debug / Anti-Frida | `_INIT_0` dans `libfoo.so` | Patch Ghidra → `RET` |
| Vérification mot de passe | Natif XOR dans `libuncrackable3.so` | Décodage Python |

---

## Étape 1 — Analyse statique avec Jadx-GUI

```bash
jadx-gui ~/Desktop/UnCrackable-Level3.apk &
```

### Points clés à observer dans `sg.vantagepoint.uncrackable3.MainActivity`

1. **`verifyLibs()`** : calcule le CRC des `.so` et du `classes.dex`. Si le CRC ne correspond pas → `tampered = 31337`
2. **`onCreate()`** : appelle `showDialog()` si root détecté ou `tampered != 0` → quitte l'app
3. **`verify()`** : délègue la vérification du mot de passe à `check.check_code()` (méthode **native**)
4. **`System.loadLibrary("foo")`** : charge `libfoo.so` qui contient les protections natives



---

## Étape 2 — Décompiler avec apktool

```bash
cd ~/Desktop
apktool d UnCrackable-Level3.apk -o uncrackable3
ls uncrackable3/lib/
# → arm64-v8a  armeabi-v7a  x86  x86_64
```

<img width="920" height="364" alt="image" src="https://github.com/user-attachments/assets/bc56545f-82d6-4b4f-95f0-ba83c26c81cd" />


---

## Étape 3 — Patch smali (anti-root + anti-tamper)

### Fichier cible
```
uncrackable3/smali/sg/vantagepoint/uncrackable3/MainActivity.smali
```

### Patch A — Neutraliser le popup "Rooting or tampering detected"

Localiser le bloc dans `onCreate()` :
```bash
grep -n "showDialog\|cond_0\|cond_1\|tampered\|return-void" \
  ~/Desktop/uncrackable3/smali/sg/vantagepoint/uncrackable3/MainActivity.smali
```

Remplacer la ligne `invoke-direct {...showDialog...}` par `return-void` :
```bash
# Identifier le numéro de ligne exact (ici 547 dans notre cas)
sed -i '547s/.*/    return-void/' \
  ~/Desktop/uncrackable3/smali/sg/vantagepoint/uncrackable3/MainActivity.smali
```
<img width="944" height="500" alt="image" src="https://github.com/user-attachments/assets/7f4bd330-a59f-45fa-8245-9a303f294cec" />
<img width="873" height="262" alt="image" src="https://github.com/user-attachments/assets/a2b28ce9-8edc-4a99-8a82-f298c310e9b7" />

**Résultat attendu dans le smali :**
```smali
    :cond_0
    return-void
    .line 130
    :cond_1
    new-instance v0, Lsg/vantagepoint/uncrackable3/CodeCheck;
```

### Patch B — Vider `verifyLibs()` (contournement du CRC)

La méthode `verifyLibs()` vérifie les CRC des librairies. Comme on va modifier `libfoo.so`, le CRC sera invalide → il faut vider cette méthode.

```bash
python3 << 'EOF'
path = '/home/kali/Desktop/uncrackable3/smali/sg/vantagepoint/uncrackable3/MainActivity.smali'

with open(path, 'r') as f:
    lines = f.readlines()

# Remplacer tout le contenu de verifyLibs (lignes 108-468) par return-void
# (adapter les indices selon votre fichier)
new_verifylibs = '    .locals 0\n    return-void\n'
lines[107:468] = [new_verifylibs]

with open(path, 'w') as f:
    f.writelines(lines)

print("✅ verifyLibs() vidée !")
EOF
```
<img width="808" height="66" alt="image" src="https://github.com/user-attachments/assets/34249dff-7e45-4d66-8dc8-57f9d226fedf" />

**Vérification :**
```bash
sed -n '107,111p' ~/Desktop/uncrackable3/smali/sg/vantagepoint/uncrackable3/MainActivity.smali
```
```smali
.method private verifyLibs()V
    .locals 0
    return-void
.end method
```
<img width="850" height="134" alt="image" src="https://github.com/user-attachments/assets/34431ed6-2e08-4a51-ad62-ebccec0687cd" />

---

## Étape 4 — Patch de libfoo.so avec Ghidra (anti-debug + anti-Frida)

### Ouvrir Ghidra
```bash
ghidra &
```

1. **New Project** → Non-Shared Project → nom : `uncrackable3`
2. **Import File** → `~/Desktop/uncrackable3/lib/x86_64/libfoo.so`
3. Double-clic → **Analyze** → OK

### Identifier la fonction anti-debug

Dans **Program Trees** → double-clic sur **`.init_array`**  
→ Voir `_INIT_0` référencé → double-clic dessus

Dans le **Décompileur**, on observe :
- La fonction lance un `pthread_create` pour surveiller Frida
- Elle appelle `goodbye()` pour tuer le processus si détection
- Elle utilise `ptrace` pour l'anti-debug

<img width="1644" height="776" alt="Capture d&#39;écran 2026-05-24 101729" src="https://github.com/user-attachments/assets/b4009566-9a5a-46dc-83f1-f66caabdc1b6" />


### Patcher `_INIT_0`

1. Dans la vue **Listing**, localiser l'adresse `001038a0` (première instruction : `SUB RSP, 0x18`)
2. **Clic droit** → **Patch Instruction**
3. Taper `RET` → **Entrée**

**Résultat dans le décompileur :**
```c
void _INIT_0(void) {
    return;
}
```

<img width="953" height="574" alt="Capture d&#39;écran 2026-05-24 102136" src="https://github.com/user-attachments/assets/40cae161-4b50-4dbc-9f64-49d968fed750" />


### Exporter la librairie patchée

**File** → **Export Program** → Format : **Original File**  
→ Destination : `/home/kali/Desktop/uncrackable3/lib/x86_64/libfoo.so`
<img width="894" height="445" alt="Capture d&#39;écran 2026-05-24 102236" src="https://github.com/user-attachments/assets/431fd09a-84a6-4ff1-928c-f8e061c0e0cc" />

---

## Étape 5 — Recompiler, Signer et Installer

### Recompiler
```bash
cd ~/Desktop
apktool b uncrackable3 -o UnCrackable-Level3-patched.apk --use-aapt2
```
<img width="943" height="232" alt="Capture d&#39;écran 2026-05-24 102357" src="https://github.com/user-attachments/assets/11f9b281-6abf-4d39-8fa9-8391a6925b15" />

### Créer et utiliser un keystore de debug
```bash
# Créer le keystore (une seule fois)
keytool -genkey -v -keystore ~/.android/debug.keystore \
  -alias androiddebugkey -keyalg RSA -keysize 2048 \
  -validity 10000 -storepass android -keypass android \
  -dname "CN=Android Debug,O=Android,C=US"

# Signer l'APK
apksigner sign --ks ~/.android/debug.keystore \
  --ks-pass pass:android \
  --key-pass pass:android \
  ~/Desktop/UnCrackable-Level3-patched.apk
```
<img width="840" height="164" alt="Capture d&#39;écran 2026-05-24 102348" src="https://github.com/user-attachments/assets/7d39d150-8d04-48db-b9de-fbd559e199f7" />

### Transférer vers Windows et installer
```bash
# Depuis Windows PowerShell
scp kali@192.168.59.132:/home/kali/Desktop/UnCrackable-Level3-patched.apk C:\Users\a\Desktop\
```

```powershell
# Sur Windows PowerShell
adb -s emulator-5556 uninstall owasp.mstg.uncrackable3
adb -s emulator-5556 install C:\Users\a\Desktop\UnCrackable-Level3-patched.apk
```
<img width="459" height="795" alt="Capture d&#39;écran 2026-05-24 103310" src="https://github.com/user-attachments/assets/c4427392-10d9-4066-a4a0-3f3fc61864ac" />


---

## Étape 6 — Analyser la logique de vérification et trouver le mot de passe

### Localiser la fonction de vérification dans Ghidra

Dans **Symbol Tree** → **Functions** → chercher :
```
Java_sg_vantagepoint_uncrackable3_CodeCheck_bar
```

Cette fonction délègue à `FUN_001012c0` (ou similaire).

### Structure de la vérification

La fonction native :
1. **Vérifie que l'entrée fait exactement 24 caractères** (`iVar1 == 0x18`)
2. **Compare octet par octet** : `octet_utilisateur == octet_référence XOR clé`
3. Les octets de référence sont stockés encodés en XOR dans le binaire

### Extraire la clé encodée

Dans Ghidra, à la fin de `FUN_001012c0`, repérer les 3 qwords (24 octets) écrits dans le buffer :

```
1d 08 11 13 0f 17 49 15  0d 00 03 19 5a 1d 13 15
08 0e 5a 00 17 08 13 14
```

### Décoder le mot de passe

```python
# decode_key.py
encoded = bytes.fromhex("1d0811130f1749150d0003195a1d1315080e5a0017081314")
xor_key = b"pizzapizzapizzapizzapizzapizza"  # clé XOR (24 octets utilisés)

secret = bytes(a ^ b for a, b in zip(encoded, xor_key))
print("Clé secrète :", secret.decode())
```
<img width="811" height="408" alt="image" src="https://github.com/user-attachments/assets/0f57f64d-9df5-4095-87e5-4776d257dd75" />

```bash
python3 decode_key.py
# 🔑 Clé secrète : making owasp great again
```

### Valider dans l'application

Taper `making owasp great again` dans le champ → cliquer **VERIFY**

<img width="357" height="781" alt="image" src="https://github.com/user-attachments/assets/c6c472f8-e80b-40a3-874d-a322f8122f1c" />


---

##  Problèmes rencontrés et solutions

### Problème 1 — `apktool b` échoue avec erreur smali
**Erreur :** `Cannot get the location of a label that hasn't been placed yet`  
**Cause :** Suppression accidentelle du label `:cond_0` lors du patch  
**Solution :** Redécompiler depuis l'APK original et refaire le patch proprement avec Python

### Problème 2 — `aapt` crash lors de la recompilation
**Erreur :** `brut.common.BrutException: could not exec (exit code = 134)`  
**Solution :**
```bash
apktool b uncrackable3 -o UnCrackable-Level3-patched.apk --use-aapt2
```

### Problème 3 — Mot de passe keystore incorrect
**Erreur :** `keystore password was incorrect`  
**Solution :** Supprimer l'ancien keystore et en créer un nouveau
```bash
rm ~/.android/debug.keystore
keytool -genkey -v -keystore ~/.android/debug.keystore \
  -alias androiddebugkey -keyalg RSA -keysize 2048 \
  -validity 10000 -storepass android -keypass android \
  -dname "CN=Android Debug,O=Android,C=US"
```

### Problème 4 — App crashe avec `SuperNotCalledException`
**Cause :** Notre `return-void` dans `onCreate()` empêchait l'appel à `super.onCreate()`  
**Solution :** Ne patcher que `verifyLibs()` et `showDialog`, pas `onCreate()` entièrement

### Problème 5 — CRC invalide après patch de libfoo.so
**Log :** `lib/x86_64/libfoo.so: Invalid checksum = X, supposed to be Y`  
**Cause :** `verifyLibs()` détecte que le CRC de libfoo.so a changé après notre patch Ghidra  
**Solution :** Vider `verifyLibs()` avec `return-void` (Patch B ci-dessus)

### Problème 6 — `adb daemon` ne démarre pas sur Windows
**Solution :**
```powershell
taskkill /F /IM adb.exe
adb start-server
adb devices
```

### Problème 7 — DNS bloque `raw.githubusercontent.com`
**Solution :**
```bash
echo "185.199.108.133 raw.githubusercontent.com" | sudo tee -a /etc/hosts
```

---

##  Concepts clés appris

### 1. Architecture d'une APK Android
```
APK
├── classes.dex     ← Bytecode Java/Kotlin (décompilé en smali)
├── lib/
│   ├── x86_64/libfoo.so      ← Librairie native (C/C++)
│   └── x86_64/libuncrackable3.so
├── AndroidManifest.xml
└── res/
```

### 2. Smali — Le bytecode Android
Smali est le langage assembleur du bytecode Dalvik/ART d'Android. Exemples :
```smali
invoke-static {}, Lclasse;->methode()Z   # appel méthode statique
move-result v0                            # stocker résultat
if-nez v0, :cond_0                        # saut si non-zéro
return-void                               # retourner sans valeur
```

### 3. Obfuscation native (Tigress / O-LLVM)
La fonction `FUN_001012c0` contient :
- **90+ malloc** répétitifs → bruit pour gêner l'analyse statique
- **Algorithme LCG** (Linear Congruential Generator) → calculs parasites
- **Listes chaînées** → structures inutiles ajoutées par l'obfuscateur
- **Données utiles cachées à la fin** → les 24 octets de la clé XOR

### 4. Pourquoi la vérification est en natif ?
| Vérification Java | Vérification Native |
|-------------------|---------------------|
| Facilement décompilée avec Jadx | Nécessite Ghidra/IDA Pro |
| Bytecode lisible | Assembleur x86/ARM |
| Pas d'obfuscation difficile | Obfuscation Tigress possible |
| Reverse trivial | Analyse longue et complexe |

---

##  Résumé des patches appliqués

| # | Fichier | Modification | Effet |
|---|---------|-------------|-------|
| 1 | `MainActivity.smali` | `invoke showDialog` → `return-void` | Supprime le popup root/tamper |
| 2 | `MainActivity.smali` | `verifyLibs()` → corps vide | Bypass vérification CRC |
| 3 | `libfoo.so` | `_INIT_0` première instruction → `RET` | Désactive anti-debug et anti-Frida |

---

##  Solution finale

**Mot de passe :** `making owasp great again`

Encodé en XOR avec la clé `pizza` (répétée sur 24 caractères), stocké dans `libuncrackable3.so`.

---
