# Padding Oracle Attack Implementation

This repository contains a Python implementation and demonstration of a **Padding Oracle Attack** against a block cipher in **CBC (Cipher Block Chaining)** mode. This attack exploits padding validation vulnerabilities to decrypt ciphertexts without the encryption key.

---

## 🔍 What is a Padding Oracle Attack?

A **Padding Oracle Attack** is a type of side-channel attack where an "oracle" (e.g., a server) tells the attacker whether the padding of a decrypted ciphertext is correct. Even if the oracle only gives a **True/False** response, this information is enough to:

- Systematically **decrypt each byte** of the ciphertext.
- Exploit **incorrect padding handling** in systems using CBC with padding schemes like **PKCS#7**.

This attack shows why **secure padding validation** and proper cryptographic practices are crucial.

---

## 📁 Files

| File        | Description                                                                 |
|-------------|-----------------------------------------------------------------------------|
| `ex1.py`    | Core script implementing the padding oracle attack logic.                   |
| `oracle.py` | Simulated "oracle" that checks decrypted padding validity.                  |
| `key.txt`   | Contains the symmetric key used by the oracle (for demo purposes only).     |
| `report.pdf`| Explains the attack methodology, implementation details, and analysis.      |

---

## 🚀 Usage

To run this demonstration, make sure Python is installed on your machine.

### 1. Clone the Repository

```bash
git clone https://github.com/RoeeHashai/Padding-Oracle-Attack.git
cd Padding-Oracle-Attack
```

### 2. Running the Demonstration

Open **two terminals**: one for the oracle, and one for the attacker script.

**Terminal 1 – Start the Oracle Server**

```bash
python oracle.py
```

**Terminal 2 – Run the Padding Oracle Attack**

```bash
python ex1.py
```

The script should demonstrate how the attacker can decrypt the ciphertext using only the padding oracle responses.

> 📄 For full details, see `report.pdf` — it explains how the attack works, how to interpret the results, and the significance of this vulnerability.

---

## ⚠️ Disclaimer

This project is for **educational and demonstrative purposes only**. It is intended to help students and security professionals understand cryptographic vulnerabilities. **Do not use** this knowledge or code for malicious purposes.

---

## 👤 Contributor

- **Roee Hashai**
