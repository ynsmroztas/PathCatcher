
# 🕵️ PathCatcher v1.0 - Path Traversal & LFI Scanner


**PathCatcher** is an advanced path traversal scanner designed for bug bounty hunters and penetration testers.  
It leverages URL archives (via `gau` or `waybackurls`) and applies custom payloads to identify Local File Inclusion (LFI) and traversal vulnerabilities.

---

## ✨ Features

- 🔍 Collects historical URLs using [gau](https://github.com/lc/gau) or [waybackurls](https://github.com/tomnomnom/waybackurls)
- 🎯 Filters URLs using `--grep` (e.g. `--grep '='` to find parametric URLs)
- 🟢 Highlights only `200 OK` responses with `--only-200`
- 💾 Logs results into a file using `-o result.txt`
- 🌐 Targets only dynamic extensions (`.php`, `.jsp`, etc.)
- 🎨 Rich terminal UI with `termcolor` and `tqdm`
- 🔐 Ignores SSL warnings by default

---

## 📦 Installation

### Requirements
```bash
pip install requests tqdm termcolor
```

### External tools
Make sure you have either:
- [`gau`](https://github.com/lc/gau) ➜ `go install github.com/lc/gau@latest`
- [`waybackurls`](https://github.com/tomnomnom/waybackurls)

---

## 🚀 Usage

```bash
python3 PathCatcher_v1.4.py -u https://example.com -p payloads.txt --grep '=' --only-200 -o result.txt
```

### Arguments

| Flag         | Description                                      |
|--------------|--------------------------------------------------|
| `-u`         | Target domain (e.g. https://example.com)         |
| `-p`         | File containing path traversal payloads          |
| `-t`         | Tool to use: `./gau` (default) or `./waybackurls`|
| `--grep`     | Filter URLs that contain a given pattern         |
| `--only-200` | Only show responses with HTTP 200 OK             |
| `-o`         | Save output to a file (e.g. result.txt)          |

---

## 📂 Example Payloads (`payloads.txt`)

```
../../../../etc/passwd
../../../../windows/win.ini
..%2f..%2f..%2f..%2fetc%2fpasswd
..\..\..\..\windows\win.ini
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

---


## 👨‍💻 Author

**mitsec**  
🔗 [x.com/ynsmroztas](https://x.com/ynsmroztas)

---

## ⚠️ Legal Disclaimer

This tool is for **educational** and **authorized testing** purposes only.  
Use it only on systems you own or have permission to test.

