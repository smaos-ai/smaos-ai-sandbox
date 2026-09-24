# ŽÁDOST O PŘIJETÍ DO REGULATORNÍHO SANDBOXU

**Věc:** Podání formální přihlášky do **Fintech Sandboxu II (CzechInvest / ČNB)** a **AI Sandboxu (Česká asociace umělé inteligence / MPO)**  
**Projekt:** Sovereign Multi-Agent Operating System (SMAOS) — Ověřitelná vrstva wire-truth governance a hardwarové atestace pro autonomní multi-agentní AI systémy  
**Žadatel:** **SovereignNexus s.r.o.**  
**IČO:** 21852084  
**Sídlo:** Praha, Česká republika  
**Zastoupená:** Andrej Leukhin, jednatel a technický ředitel (CTO)  
**ID datové schránky žadatele:** *(doplní žadatel při odeslání)*  
**Kontaktní e-mail:** `andrejlo123@gmail.com`  

---

### Adresáti (prostřednictvím Informačního systému datových schránek — ISDS):

1. **Agentura pro podporu podnikání a investic CzechInvest**  
   *Odbor podpory inovací a fintech ekosystému — Fintech Sandbox II*  
   **ID datové schránky:** `al2vhwb`  

2. **Česká národní banka (ČNB)** — *na vědomí*  
   *Sekce dohledu nad finančním trhem / Odbor dohledu nad ICT riziky a kybernetickou bezpečností*  
   **ID datové schránky:** `8tgaief`  

3. **Ministerstvo průmyslu a obchodu ČR (MPO) / Česká asociace umělé inteligence (ČAS)**  
   *Sekce digitalizace a inovací — Národní AI Regulatory Sandbox dle čl. 57–59 AI Act*  
   **ID datové schránky:** `bxtaaw4`  

---

### I. Předmět žádosti

Společnost **SovereignNexus s.r.o.** tímto formálně předkládá žádost o přijetí inovativního řešení **SMAOS v1.1.0** do testovacího a regulatorního režimu v rámci **Fintech Sandboxu II** (CzechInvest / ČNB) a souběžně do **ČAS AI Sandboxu** (MPO / ČAS).

Cílem projektu je poskytnout českým a evropským bankovním domům a regulovaným fintech institucím **první matematicky ověřitelnou, air-gapped runtime membránu** řešící selhání autonomních AI agentů na úrovni síťových a účetních operací před plnou účinností nařízení DORA (leden 2025) a nařízení o umělé inteligenci (EU AI Act, prosinec 2026).

---

### II. Klíčový problém českého finančního sektoru: „The Container Fallacy“

Současné bankovní nasazení autonomních agentů (pro úvěrový underwriting, treasury operace a vypořádání plateb) trpí strukturální zranitelností:
1. **Falešná tvrzení o stavu transakce (Overclaim Rate 75%)**: Při běžném síťovém incidentu typu `HTTP 504 Gateway Timeout` nebo přerušení spojení `TCP RST` komerční frameworky (LangChain, AutoGen, Spring AI) standardně potlačí síťovou výjimku a do interní paměti agenta falešně zapíší stav `CONFIRMED`. Výsledkem je rozpad shody mezi stavem agenta a reálnou bankovní účetní knihou (silent ledger drift) s rizikem duplicitního odeslání plateb.
2. **Regulační rozpor mezi DORA, AI Act a GDPR**:
   * **DORA čl. 17**: Povinnost detekovat a nahlásit incident do 4 hodin pod hrozbou pokuty až do výše 1 % denního obratu.
   * **EU AI Act čl. 14**: Povinnost deterministického lidského dohledu (Human Oversight) a nepřekročitelných finančních stropů.
   * **Paradox GDPR čl. 17 vs. AI Act čl. 12**: AI Act požaduje neměnný auditní log po dobu několika let, zatímco GDPR vyžaduje právo na výmaz osobních údajů (IBAN, jména). Standardní digitální podpisy (Ed25519, RSA) se při smazání jediného bytu stanou neplatnými.

---

### III. Inovativní technologické řešení SMAOS

Projekt SMAOS nahrazuje vágní textové „prompt guardrails“ **deterministickými fyzikálními a kryptografickými zárukami**:
* **W3C BBS+ BLS12-381 vektorové ZKP podpisy (`src/bbs_redactor.py`)**: Matematicky řeší paradox GDPR vs. AI Act. Umožňuje trvale vymazat IBAN klienta a zároveň regulátorovi předložit kryptografický Zero-Knowledge důkaz, že transakce byla řádně autorizována.
* **Ochrana proti de-anonymizaci (výzkum ETH Zürich / Anthropic)**: Tradiční textové maskování selhává vůči kontextové stylometrii velkých modelů (68 % recall / 90 % přesnost re-identifikace). BBS+ odděluje data na kryptografické bázi.
* **Rámec ALTAI „Human as Project Leader“ (EU AI Act čl. 14)**: Lidský operátor definuje neměnné mantinely a finanční stropy (např. 10 000 EUR v `smaos.hcl`). Pokud agent narazí na RCE volání nebo limit, systém transakci deterministicky pozastaví a přepne do fronty lidského veta bez zahlcení schvalováním rutinních úkonů.
* **Jev-Style typovaný router (`src/jev_typed_router.py`)**: Sub-milisekundový (<0,05 ms) deterministický rozhodovací mechanismus s nulovými tokenovými náklady ($0.00).
* **Copy-on-Write (COW) stavový sandbox (`src/cow_subgraph_sandbox.py`)**: Spekulativní operace při selhání sítě zůstávají izolovány v dočasné COW větvi a jsou promítnuty do hlavní paměti pouze na základě platného IETF SCITT `COSE_Sign1` potvrzení.
* **Hardwarová atestace Intel TDX / AMD SEV-SNP (`src/enclave_cvm.py`)**: Zabezpečení agentů v důvěryhodném prostředí (Confidential VM) s 1024bajtovým hardwarovým certifikátem `TDREPORT_STRUCT`.
* **Post-kvantový hybridní podpis NIST FIPS 204 ML-DSA-65 (`src/pqc_mldsa.py`)**: Odolnost proti kvantovým útokům po roce 2050+.
* **Plně validovaný registr EBA DPM 4.0 xBRL-CSV (15 šablon RT.01.01–RT.99.01)**.

---

### IV. Dosažené ověřovací metriky a bezpečnost pro sandbox

Systém je plně vyvinut, otestován a připraven k nasazení:
* **Zátěžový test (Soak Fuzzer)**: **10 000 transakcí** dokončeno s průchodností **14 619 tx/sec** při latenci **0,067 ms** a **0,0 % chybovosti (Overclaim Rate = 0,00 %)** za simulace 75% poruchovosti sítě.
* **Jednotkové a integrační testy**: **65/65 testů PASSED**, 42/42 hraničních podmínek splněno.
* **Bezpečnost testování (Zero Egress)**: SMAOS běží v plně izolovaném režimu na `127.0.0.1` (`--network none`). Žádná data, telemetrie ani klíče neopouštějí lokální hardware žadatele / partnerské banky. Nedochází k žádnému napojení na produkční platební systémy (SWIFT, CERTIS, SEPA).

---

### V. Seznam přiložených dokumentů

1. **Kompletní předkládací zpráva (Regulatory Submission Dossier v1.1.0)** — `REGULATORY_SANDBOX_SUBMISSION_DOSSIER.md` (PDF/A formát).
2. **Strojově čitelný balíček registru DORA dle EBA DPM 4.0** — `DORA_Register_DPM40_EBA_ITS_2024_2956.zip`.
3. **Kryptografické potvrzení SCITT a atestace** — `audit_out/trust_passport.cose.json`, `audit_out/rekor_receipt.json`.
4. **Zero-Knowledge BBS+ odvozený důkaz** — `audit_out/bbs_derived_proof.json`.
5. **Technická specifikace a otevřený kód** — dostupné na repozitáři: `https://github.com/smaos-ai/smaos-ai-sandbox`.

---

### VI. Závěr a podpis

Společnost **SovereignNexus s.r.o.** deklaruje plnou připravenost k zahájení úvodního technického dialogu s expertní komisí CzechInvestu, zástupci České národní banky a České asociace umělé inteligence.

V Praze dne 24. září 2026

____________________________________________  
**Andrej Leukhin**  
Jednatel a technický ředitel (CTO)  
SovereignNexus s.r.o.  
IČO: 21852084  
E-mail: `andrejlo123@gmail.com`  
Web / GitHub: `https://github.com/smaos-ai/smaos-ai-sandbox`
