# Movie - HackMyVM (Medium)

![Movie.png](Movie.png)

## Übersicht

*   **VM:** Movie
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Movie)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 5. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Movie_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Movie" zu erlangen. Der initiale Zugriff erfolgte durch das Ausnutzen einer Server-Side Request Forgery (SSRF)-Schwachstelle in einer Dateiupload-Funktion (`upload.php`). Durch das Hochladen einer präparierten AVI-Datei, die `ffmpeg` anwies, eine lokale Datei (`/var/www/html/data/config.php`) zu lesen, konnten Datenbank-Credentials (`tarantino:killer`) extrahiert werden. Parallel dazu wurde eine passwortgeschützte ZIP-Datei (`mydata_archive.zip`) gefunden. Nach dem Knacken der ZipCrypto-Verschlüsselung mit `bkcrack` (unter Verwendung bekannter interner Schlüssel) wurde ein privater SSH-Schlüssel für den Benutzer `tarantino` extrahiert. Mit diesem Schlüssel oder den Datenbank-Credentials (die auch für SSH funktionierten) wurde SSH-Zugriff als `tarantino` erlangt. Die finale Rechteausweitung zu Root gelang durch Ausnutzung einer unsicheren `sudo`-Regel, die `tarantino` erlaubte, `/usr/bin/nano /etc/passwd` ohne Passwort auszuführen. Obwohl `/etc/passwd` immutable war, konnte die Befehlsausführungsfunktion innerhalb von `nano` genutzt werden, um eine SUID-Root-Shell zu erstellen. Eine alternative, komplexere Route zu Root involvierte eine LFI-Schwachstelle und die Ausnutzung von `sudo qrencode`.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi` / `nano`
*   `nmap`
*   `gobuster`
*   `wget`
*   Python (`gen_avi.py` für SSRF)
*   `fcrackzip` (versucht)
*   `bkcrack`
*   `zip` / `unzip`
*   `chmod`
*   `ssh`
*   `sudo`
*   `lsattr`
*   `curl`
*   `echo`
*   `nc` (netcat)
*   `stty`
*   `qrencode`
*   Standard Linux-Befehle (`ls`, `cat`, `mv`, `id`, `fg`, `export`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Movie" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.117) mit `arp-scan` identifiziert. Hostname `movie.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 8.4p1) und Port 80 (HTTP, Apache 2.4.54) mit dem Titel "movie.hmv".
    *   `gobuster` fand u.a. `/upload.php` und das Verzeichnis `/data/` (mit `login.php`, `config.php` (leer)).

2.  **SSRF & Credential/Key Extraction:**
    *   Eine SSRF-Schwachstelle wurde in `ffmpeg` (ausgelöst durch `upload.php`) vermutet.
    *   Mittels `gen_avi.py` wurde eine AVI-Datei erstellt, die `ffmpeg` anwies, `file:///var/www/html/data/config.php` zu lesen.
    *   Nach dem Upload der AVI über `upload.php` und dem Download der konvertierten MP4-Datei wurden Datenbank-Credentials (`tarantino:killer`) aus der MP4-Datei extrahiert.
    *   Parallel (oder alternativ) wurde eine passwortgeschützte ZIP-Datei (`mydata_archive.zip`, Herkunft im Log unklar) gefunden. Mittels `bkcrack` und bekannten internen Schlüsseln (`d706e724 da372a68 a79864b0`) wurde die Verschlüsselung gebrochen.
    *   Aus dem entschlüsselten ZIP-Archiv wurde ein privater SSH-Schlüssel (`id_rsa`) für den Benutzer `tarantino` extrahiert.

3.  **Initial Access (SSH als `tarantino`):**
    *   Erfolgreicher SSH-Login als `tarantino` mit dem extrahierten privaten Schlüssel `id_rsa` (oder den Credentials `tarantino:killer`).
    *   Die User-Flag (`0508e6506868d4b9d3f8545054d3e8db`) wurde in `/home/tarantino/user.txt` gefunden.

4.  **Privilege Escalation (von `tarantino` zu `root` via `sudo nano`):**
    *   `sudo -l` als `tarantino` zeigte, dass `/usr/bin/nano /etc/passwd` als `root` ohne Passwort ausgeführt werden durfte.
    *   `lsattr /etc/passwd` zeigte, dass die Datei immutable (`i`-Attribut) war, was direkte Änderungen verhinderte.
    *   Trotzdem wurde `sudo /usr/bin/nano /etc/passwd` ausgeführt. Innerhalb von `nano` wurde mittels `Ctrl+T` (Execute Command) der Befehl `chmod u+s /bin/bash` ausgeführt.
    *   Nach dem Verlassen von `nano` wurde mit `/bin/bash -p` eine Root-Shell erlangt (`euid=0(root)`).
    *   Die Root-Flag (`dff82e2a59c62c1884b32973fd6e6f52`) wurde in `/root/root.txt` gefunden.

5.  **Alternative Route zu Root (LFI -> RCE -> `sudo qrencode`):**
    *   Eine LFI-Schwachstelle wurde in `index.php` (Parameter `get_page`) identifiziert.
    *   Eine PHP-Webshell wurde in `/dev/shm/shell.php` geschrieben.
    *   Mittels LFI und der Webshell (`curl "http://localhost/index.php?get_page=../../../dev/shm/shell.php&cmd=..."`) wurde eine Reverse Shell als `www-data` erlangt.
    *   Als `www-data` wurde festgestellt, dass `/usr/bin/qrencode -r /root/.ssh/id_rsa -o /tmp/root` mit `sudo` ausgeführt werden durfte.
    *   Der Root-SSH-Key wurde als QR-Code in `/tmp/root_qr.png` gespeichert, per `nc` exfiltriert, mit einem QR-Decoder gelesen und für einen SSH-Root-Login verwendet.

## Wichtige Schwachstellen und Konzepte

*   **Server-Side Request Forgery (SSRF) via `ffmpeg`:** Eine Dateiupload-Funktion verarbeitete Videos unsicher mit `ffmpeg`, was das Auslesen lokaler Dateien ermöglichte.
*   **Schwache ZIP-Verschlüsselung (ZipCrypto) / Bekannte Schlüssel:** Ein ZIP-Archiv war mit ZipCrypto verschlüsselt und konnte mit `bkcrack` und bekannten internen Schlüsseln entschlüsselt werden, was zur Preisgabe eines SSH-Schlüssels führte.
*   **Preisgabe von Credentials/Schlüsseln:** Datenbank-Credentials in einer durch SSRF ausgelesenen Datei; SSH-Schlüssel in einem entschlüsselten ZIP-Archiv.
*   **Unsichere `sudo`-Regeln:**
    *   `tarantino` durfte `nano /etc/passwd` als Root ausführen. Obwohl die Datei immutable war, erlaubte die Befehlsausführung innerhalb von `nano` die Eskalation.
    *   (Alternativer Pfad) `www-data` durfte `qrencode` mit Root-Rechten verwenden, um beliebige Dateien zu lesen und als QR-Code zu exfiltrieren.
*   **Local File Inclusion (LFI):** (Alternativer Pfad) Eine LFI in `index.php` ermöglichte das Ausführen einer zuvor hochgeladenen Webshell.
*   **Immutable File Attribute Bypass:** Das `i`-Attribut auf `/etc/passwd` verhinderte direkte Änderungen, aber nicht die Befehlsausführung durch einen als Root laufenden Editor.

## Flags

*   **User Flag (`/home/tarantino/user.txt`):** `0508e6506868d4b9d3f8545054d3e8db`
*   **Root Flag (`/root/root.txt`):** `dff82e2a59c62c1884b32973fd6e6f52`

## Tags

`HackMyVM`, `Movie`, `Medium`, `SSRF`, `ffmpeg Exploit`, `ZipCrypto Crack`, `bkcrack`, `SSH Key Leak`, `sudo Exploit`, `nano Exploit`, `LFI`, `qrencode Exploit`, `Linux`, `Web`, `Privilege Escalation`, `Apache`
