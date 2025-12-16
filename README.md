# 🕰️ Chronos-Track
### Active Remote Physical Device Fingerprinting Engine

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Language](https://img.shields.io/badge/lang-Rust_1.7+-orange?logo=rust)
![Architecture](https://img.shields.io/badge/arch-x86__64_%7C_aarch64-blueviolet)
![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/release-v1.2-purple)

> **"Hardware never lies."**

**Chronos-Track** מודדת Clock Skew באמצעות ניתוח סטיות מיקרוסקופיות ב‑TCP Timestamps. המערכת שולחת סייני SYN עם אופציית Timestamp, לוכדת את תגובות היעד בדיוק ננו־שניות, ומבצעת רגרסיה על מעטפת קמורה תחתונה כדי לזהות חתימת קוורץ פיזית מול חותמות זמן וירטואליות מסונכרנות.

---

## ⚡ Key Capabilities (v1.2)

| Feature | Description |
| :--- | :--- |
| **Active Hunter Mode** | Injector רמת Layer‑3 שבונה מנות SYN עם TSopt וקובע את ה‑source IP בכל מחזור. |
| **👻 Stealth Jitter** | מרווחי שליחה אדפטיביים (10–500 ms) עם ג'יטר אקראי למניעת דפוסי IDS. |
| **🧠 Math Core** | Convex Hull Lower-Bound + רגרסיה ליניארית שמנטרלת נקודות רעש ומחזירה ppm, slope ו‑$R^2$. |
| **🛡️ RstGuard** | הוספה/הסרה אוטומטית של חוקת `iptables` לדיכוי RST מקומיים (source port 54321). |
| **📺 Live TUI** | ממשק Ratatui מציג סטטוס סשן, גרף פיזור + קו רגרסיה, ולוח מודיעין (“🧠 CHRONOS INTELLIGENCE”). |
| **📦 Data Export** | כתיבה רציפה ל‑`measurements.csv` + סקריפט Python (`plot.py`) ליצירת גרפי Convex Hull.

### Why This Matters

- **Hardware truthing:** Clock skew פיזי נשמר גם מאחורי VPN/NAT ולכן מסייע להבדיל בין שרת אמיתי לבין Honeypot וירטואלי.
- **Noise rejection:** שימוש ב‑SO_TIMESTAMPING + Hull מוריד jitter מהרשת ומאפשר לטפל בקישורים עמוסים.
- **שילוב מודיעיני:** Live verdictים מאפשרים קבלת החלטה במקום ולהמשיך לניתוח Offline עם החומר הגולמי.

---

## 🔬 Theory of Operation

כל אוסצילטור קוורץ סוטה בתדרו מ‑$f_{nominal}$. Chronos-Track מודד את השיפוע בין $T_{ts}$ (שעון היעד) לבין $t_{rx}$ (שעון מקומי):

$$\alpha = \frac{f_{actual} - f_{nominal}}{f_{nominal}}$$

- **Physical Hardware:** מציג Drift ליניארי ו‑$R^2$ גבוה (≥ 0.99).
- **Virtual / Honeypot:** מציג שיפועים אפסיים, קפיצות, או רעש כאוטי בעקבות סנכרון ל‑Host.

### Data Products

- `measurements.csv` – רשומה אחת לכל חבילה: `kernel_time_ns,sender_ts_val,src_ip`.
- `graphs/fingerprint_*.png` – נוצר ע"י `python plot.py`, כולל ענן נקודות + Convex Hull.
- דוח יציאה – בעת `Ctrl+C` מתקבלות סטטיסטיקות (Samples, slope, ppm, $R^2$, verdict + תיאור מילולי).

---

## 🛠️ System Architecture

```mermaid
graph TD;
    A[Injector Tx] -->|Raw SYN + TSopt| B(Target Host);
    B -->|SYN-ACK + TSval| C[Sniffer Rx];
    C -->|SO_TIMESTAMPING| D{Analysis Core};
    D -->|Observations| E[Convex Hull Regression];
    E -->|ppm, R², Verdict| F[TUI + CSV];
````

### Pipeline Overview

1. **Injector** – PNET Layer‑3 ערוץ, בונה IPv4/TCP + אופציית Timestamp (TSval קבועה) ומוסיף jitter.
2. **RstGuard** – מציב חוקת iptables `OUTPUT` לדיכוי `RST` מקומי ומנקה אותה ב‑Drop.
3. **Sniffer** – `AF_PACKET/SO_TIMESTAMPING` עם `recvmsg` ו‑CMSG parsing שמחלץ חותמות זמן ננו־שניות.
4. **Analysis** – מייצר `Observation`‎‑ים, מחשב מעטפת קמורה תחתונה, מסיק slope→ppm→Verdict ופרשנות.
5. **UI & Logging** – Ratatui + `env_logger`; כל 50 Samples נשלח log INFO ועידכון תצוגה.

---

## 📊 Proof of Concept
![Graph](graphs/demo.png)
> **Figure 1:** Convex Hull (אדום) מעל ענן הדגימות ממחיש את ה‑drift הליניארי של יעד פיזי.

---

## 🚀 Usage

### Prerequisites

- לינוקס (כולל WSL2) עם `AF_PACKET` ו‑`SO_TIMESTAMPING`.
- הרשאות `CAP_NET_RAW` + גישה ל‑`iptables`.
- מומלץ: `ethtool -K <iface> tx off rx off` כדי לנטרל offload בזמן בדיקה.

### Build

```bash
cargo build --release
```

### CLI Flags

| Flag | Required | Description |
| :--- | :--- | :--- |
| `--interface <IFACE>` | ✅ | הממשק ללכידה והאזנה (משמש את Socket ה‑AF_PACKET). |
| `--target-ip <IPv4>` | ✅ | יעד להזרקה. IPv6 נתמך ללכידה פסיבית בלבד והקריאה תידחה אם יינתן IPv6. |
| `--target-port <u16>` | ❌ | פורט היעד ל‑SYN (ברירת מחדל 80). |

> נדרש להפעיל כ־root או להעניק יכולות (`setcap cap_net_raw+ep target/release/chronos_track`).

### Run

```bash
RUST_LOG=info sudo -E ./target/release/chronos_track \
    --interface eth0 \
    --target-ip 203.0.113.42 \
    --target-port 443
```

### Runtime Controls

- `Ctrl+C` – עוצר את ה־injector/sniffer, סוגר את ממשק ה‑TUI ומדפיס Exit Report.
- `q` / `Q` – סוגר את ה‑TUI בלבד (גם כן מפסיק את הסשן).
- פלט INFO כל 50 דגימות מציג נקודות, slope, ppm, $R^2$, verdict ומרווח ההזרקה החדש.

### Outputs

```text
=== Chronos-Track Exit Report ===
Samples captured: 312
Slope: 0.999873219
Clock Skew: -126.8 ppm
R²: 0.9987
Classification: Stable Physical Quartz Signature
--- 🧠 CHRONOS INTELLIGENCE ---
Signal Quality: Stable (Typical Physical Device)
Hardware Est.:  Consumer Hardware (PC/Laptop)
FINAL VERDICT:  Likely a consumer workstation or laptop behind NAT.
--------------------------------
```

להפקת גרף Offline:

```bash
python plot.py  # יוצר graphs/fingerprint_<ip>_<timestamp>.png
```

---

## 🔧 Limitations & Notes

- ה‑Injector תומך כרגע ב‑IPv4 בלבד; ניתן להריץ Passive Sniffing אם מציינים יעד IPv4 אך לא מתקבלות תשובות.
- `measurements.csv` נכתב מחדש בכל ריצה – יש לגבות לפני סשן נוסף.
- ה‑Injector רץ בלולאה אינסופית עד שהדגל `running` מכובה; אין CLI לעצירתו בנפרד.
- דרוש `iptables` בסביבה (למשל ב‑WSL יש להפעיל אותו במכונה הנכונה).

---

## 🗺️ Roadmap to v2.0 (Mass Scanner)

- [x] v1.2 – Active single target + Ratatui + Convex Hull Math Core.
- [ ] v2.0 – ארכיטקטורת Tokio אסינכרונית, מעקב אחר עשרות יעדים במקביל, DashMap state + יצוא JSON.

📄 **Architecture v2 draft** – בעבודה (מסמך פנימי).

---

## 🤝 Contributing

נשמח ל‑PRs עבור:

- תמיכה באוספים נוספים (QUIC/ICMP timestamps).
- Dashboards / Jupyter notebooks לחקר הנתונים.
- חיזוק הקשחת סביבה (AppArmor/SELinux, קונטיינרים, WFP ב‑Windows).

נא לפתוח issue לפני רפקטור משמעותי.

## ⚠️ Disclaimer

השימוש בכלי מיועד למחקר הגנתי, בדיקות Red/Blue בתוך גבולות חוקיים, ולתשתיות שבבעלותכם בלבד. הפעלת סריקות כלפי צד שלישי ללא אישור – אסורה ועל אחריות המשתמש בלבד.

```
```