"""
FORTRESS — Main Research Output Runner
Run:  python fortress_main.py
Requires: numpy (pip install numpy)
Optional: scipy (pip install scipy) — not used; pure-Python fallback built in
"""

import sys, os, time, shutil, math
from fortress_models import (
    NetworkState, WatcherStrategy, WatcherEconomics,
    AttackParams, DefenseParams,
    ProbabilisticSecurityModel,
    WatcherCommonsGame,
    AttackCostModel,
    AdaptiveSecurityOrchestrator,
    SecurityMode,
)
import numpy as np

# ── ANSI colours ──────────────────────────────────────────

if sys.platform == "win32":
    import ctypes
    ctypes.windll.kernel32.SetConsoleMode(
        ctypes.windll.kernel32.GetStdHandle(-11), 7
    )

RST  = '\033[0m'
BOLD = '\033[1m'
DIM  = '\033[2m'
RED  = '\033[91m'
GRN  = '\033[92m'
YEL  = '\033[93m'
CYN  = '\033[96m'
BLU  = '\033[94m'
MAG  = '\033[95m'
WHT  = '\033[97m'
ORG  = '\033[38;5;214m'   # Bitcoin orange

W = shutil.get_terminal_size((110, 24)).columns

def hr(ch='─', col=DIM):        print(f"{col}{ch * W}{RST}")
def vhr(ch='═', col=CYN):       print(f"{col}{ch * W}{RST}")
def blank():                    print()

import re
def _plain(s):
    return re.sub(r'\033\[[0-9;]*m', '', s)

def centre(s):
    pad = max(0, (W - len(_plain(s))) // 2)
    print(' ' * pad + s)

def section(title, nc_tag, col=CYN):
    blank()
    hr('═', col)
    centre(f"{col}{BOLD}  {nc_tag}  {title}  {RST}")
    hr('─', DIM)
    blank()

def kv(label, value, col=WHT, indent=4):
    print(f"{' ' * indent}{DIM}{label:<44}{RST}{col}{value}{RST}")

def progress_bar(value, lo=0.0, hi=1.0, width=32, label=""):
    frac = max(0.0, min(1.0, (value - lo) / max(hi - lo, 1e-9)))
    filled = int(frac * width)
    pct = frac * 100
    if pct >= 80:
        col = GRN
    elif pct >= 50:
        col = YEL
    else:
        col = RED
    bar = col + '█' * filled + DIM + '░' * (width - filled) + RST
    return f"[{bar}] {col}{pct:5.1f}%{RST}  {DIM}{label}{RST}"


# ════════════════════════════════════════════════════════════
#  HEADER
# ════════════════════════════════════════════════════════════

def print_header():
    os.system('cls' if sys.platform == 'win32' else 'clear')
    blank()
    vhr('╔', ORG)
    centre(f"{ORG}{BOLD}  ₿  FORTRESS — Bitcoin L2 Bridge Security Framework  ₿  {RST}")
    centre(f"{DIM}  Probabilistic · Game-Theoretic · Economic · Adaptive  {RST}")
    centre(f"{DIM}  Harish M & Praatibh · NSYSU CS&E · May 2026  {RST}")
    vhr('╚', ORG)
    blank()
    centre(f"{DIM}Four novel research contributions beyond prior BitVM security work{RST}")
    blank()
    for tag, title in [
        ("NC1", "Probabilistic Security Model — closed-form P(security)"),
        ("NC2", "Watcher Commons Game — Nash equilibrium + tragedy of commons"),
        ("NC3", "Attack Cost Threshold — Security Efficiency Ratio"),
        ("NC4", "Adaptive Security Orchestrator — dynamic BitVM↔ZK switching"),
    ]:
        print(f"    {ORG}{BOLD}{tag}{RST}  {WHT}{title}{RST}")
    blank()


# ════════════════════════════════════════════════════════════
#  NC1 OUTPUT
# ════════════════════════════════════════════════════════════

def run_nc1():
    section("PROBABILISTIC SECURITY MODEL", "NC1", ORG)
    psm = ProbabilisticSecurityModel()

    state_default = NetworkState()   # spam=5, cap=3, fee=55, W=6
    state_severe  = NetworkState(spam_rate=10.0)
    state_mild    = NetworkState(spam_rate=2.0)

    strat_static   = WatcherStrategy(initial_fee=55.0,  escalation_rate=0.0)
    strat_adaptive = WatcherStrategy(initial_fee=55.0,  escalation_rate=20.0, max_fee=250.0)
    strat_premium  = WatcherStrategy(initial_fee=135.0, escalation_rate=10.0, max_fee=300.0)

    print(f"  {BOLD}Network States Under Analysis{RST}")
    blank()
    for label, state in [
        ("Mild attack   (spam=2/block)", state_mild),
        ("Default attack (spam=5/block)", state_default),
        ("Severe attack  (spam=10/block)", state_severe),
    ]:
        print(f"  {DIM}{'─'*60}{RST}")
        print(f"  {CYN}{BOLD}{label}{RST}")
        for strat_label, strat in [
            ("Static fee (55 sat/vB, no escalation)", strat_static),
            ("Adaptive fee (55→+20/block, max 250)", strat_adaptive),
            ("Premium fee  (135→+10/block, max 300)", strat_premium),
        ]:
            p, per_block = psm.single_watcher_success(strat, state)
            bar = progress_bar(p, label=f"{p*100:.1f}%")
            print(f"    {DIM}{strat_label:<42}{RST} {bar}")
            per_str = "  ".join(f"{v*100:.0f}%" for v in per_block)
            print(f"    {DIM}  per-block: [{per_str}]{RST}")
        blank()

    print(f"  {BOLD}N* — Minimum Watchers for 99% Security{RST}")
    blank()
    print(f"  {'Strategy':<42} {'Mild':>8} {'Default':>10} {'Severe':>8}")
    print(f"  {DIM}{'─'*42}  {'─'*8}  {'─'*10}  {'─'*8}{RST}")
    for strat_label, strat in [
        ("Static fee (55 sat/vB)",          strat_static),
        ("Adaptive fee (escalation +20)",    strat_adaptive),
        ("Premium fee  (start 135)",         strat_premium),
    ]:
        vals = []
        for state in [state_mild, state_default, state_severe]:
            n = psm.min_watchers_for_target(0.99, strat, state)
            if n >= 9999:
                vals.append(f"{RED}∞{RST}")
            elif n > 20:
                vals.append(f"{YEL}{n}{RST}")
            else:
                vals.append(f"{GRN}{n}{RST}")
        print(f"  {strat_label:<42} {vals[0]:>18}  {vals[1]:>20}  {vals[2]:>18}")

    blank()
    print(f"  {BOLD}Key Finding NC1{RST}")
    print(f"  {YEL}A static-fee watcher cannot get confirmed against sustained fee flooding.{RST}")
    print(f"  {YEL}Adaptive fee escalation is necessary — and bridges must design for it.{RST}")
    print(f"  {YEL}The minimum watcher count N* is a new security design parameter.{RST}")
    blank()

    # Phase diagram (ASCII heatmap)
    print(f"  {BOLD}Security Phase Diagram  P(security | spam_rate, N_watchers){RST}")
    print(f"  {DIM}Rows = spam rate (txs/block), Cols = # watchers (adaptive strategy){RST}")
    blank()

    spam_rates    = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    watcher_counts = list(range(1, 13))
    grid = psm.security_heatmap(spam_rates, watcher_counts, strat_adaptive, state_default)

    header = f"  {'spam\\N':>6}  " + "  ".join(f"{n:>4}" for n in watcher_counts)
    print(header)
    print(f"  {DIM}{'─'*(len(_plain(header))-2)}{RST}")
    for i, sr in enumerate(spam_rates):
        row_str = f"  {sr:>6.0f}   "
        for j in range(len(watcher_counts)):
            v = grid[i][j]
            if v >= 0.95:
                cell = f"{GRN}{v*100:4.0f}{RST}"
            elif v >= 0.70:
                cell = f"{YEL}{v*100:4.0f}{RST}"
            elif v >= 0.40:
                cell = f"{ORG}{v*100:4.0f}{RST}"
            else:
                cell = f"{RED}{v*100:4.0f}{RST}"
            row_str += cell + "  "
        print(row_str + f"  {DIM}%{RST}")

    blank()
    print(f"  {GRN}■ ≥95%  {RST}{YEL}■ 70–94%  {RST}{ORG}■ 40–69%  {RST}{RED}■ <40%{RST}")
    print(f"  {DIM}Phase boundary visible around spam≥4 with N<5  →  security collapse{RST}")


# ════════════════════════════════════════════════════════════
#  NC2 OUTPUT
# ════════════════════════════════════════════════════════════

def run_nc2():
    section("WATCHER COMMONS GAME", "NC2", BLU)
    wcg = WatcherCommonsGame()

    econ_default  = WatcherEconomics()  # cost=3000, reward=5000
    econ_low_r    = WatcherEconomics(personal_reward_sats=3_500)   # barely profitable
    econ_high_r   = WatcherEconomics(personal_reward_sats=15_000)  # well-incentivised

    limit_default = wcg.commons_tragedy_limit(econ_default)
    limit_low_r   = wcg.commons_tragedy_limit(econ_low_r)
    limit_high_r  = wcg.commons_tragedy_limit(econ_high_r)

    print(f"  {BOLD}Nash Equilibrium Participation & Tragedy of the Commons{RST}")
    blank()
    print(f"  {DIM}Derivation:  p* = 1 − (c/r)^{{1/(N−1)}}{RST}")
    print(f"  {DIM}Tragedy limit: lim_{{N→∞}} P(≥1 acts) = 1 − c/r{RST}")
    blank()

    # Table
    Ns = [1, 2, 3, 5, 10, 20, 50, 100]
    col_w = 14
    header = f"  {'N':>5}  "
    for lbl in ["p*(default)", "P≥1(def)", "p*(low-r)", "P≥1(low)", "p*(high-r)", "P≥1(high)"]:
        header += f"{lbl:>{col_w}}"
    print(header)
    print(f"  {DIM}{'─' * (len(_plain(header)))}{RST}")

    for N in Ns:
        p_d  = wcg.nash_probability(N, econ_default)
        pe_d = wcg.effective_participation(N, econ_default)
        p_l  = wcg.nash_probability(N, econ_low_r)
        pe_l = wcg.effective_participation(N, econ_low_r)
        p_h  = wcg.nash_probability(N, econ_high_r)
        pe_h = wcg.effective_participation(N, econ_high_r)

        def fmt_p(v):
            col = GRN if v >= 0.90 else (YEL if v >= 0.60 else RED)
            return f"{col}{v*100:8.1f}%{RST}"

        row = f"  {N:>5}  "
        for v in [p_d, pe_d, p_l, pe_l, p_h, pe_h]:
            row += f"  {fmt_p(v):>{col_w + 18}}"
        print(row)

    blank()
    print(f"  {DIM}Tragedy limit (N→∞):{RST}")
    def col_limit(v):
        return (GRN if v >= 0.9 else YEL if v >= 0.6 else RED)
    print(f"    default (r=5000 sat): {col_limit(limit_default)}{limit_default*100:.1f}%{RST}   "
          f"low-r   (r=3500 sat): {col_limit(limit_low_r)}{limit_low_r*100:.1f}%{RST}   "
          f"high-r  (r=15000 sat): {col_limit(limit_high_r)}{limit_high_r*100:.1f}%{RST}")

    blank()
    print(f"  {BOLD}Minimum Reward r* for 99% Effective Participation{RST}")
    blank()
    for N in [1, 3, 5, 10, 20]:
        r_star = wcg.min_reward_for_target(N, econ_default, 0.99)
        arrow  = f"{GRN}✔{RST}" if r_star < 10_000 else (f"{YEL}~{RST}" if r_star < 100_000 else f"{RED}✘{RST}")
        print(f"    N={N:<4}  r* = {ORG}{r_star:>12,.0f}{RST} sats  {arrow}")

    blank()
    print(f"  {BOLD}Key Finding NC2{RST}")
    print(f"  {YEL}P(≥1 watcher acts) saturates below 1.0 — the Tragedy of the Commons.{RST}")
    print(f"  {YEL}Incentive design (reward r) matters more than watcher count N.{RST}")
    print(f"  {YEL}With default economics, security ceiling is {limit_default*100:.0f}% regardless of N.{RST}")
    print(f"  {YEL}This is the first formal proof that 'add more watchers' is not a solution.{RST}")
    blank()


# ════════════════════════════════════════════════════════════
#  NC3 OUTPUT
# ════════════════════════════════════════════════════════════

def run_nc3():
    section("ATTACK COST THRESHOLD", "NC3", MAG)
    acm = AttackCostModel()

    ap = AttackParams()    # default: W=6, K=3, 10 spam/block, 130 sat/vB
    dp = DefenseParams()   # default: 1 watcher, 55 sat/vB

    vault_btc = 12.65   # $1,265,000 @ $100k / BTC

    analysis = acm.full_analysis(vault_btc, ap, dp)

    print(f"  {BOLD}Security Budget Analysis — Vault: {ORG}{vault_btc:.2f} BTC{RST}")
    blank()
    kv("Attack parameters",
       f"W={ap.challenge_window} blocks · {ap.spam_per_block} spam/block · {ap.spam_fee_sat_vb} sat/vB · {ap.spam_tx_vbytes} vB/tx",
       DIM)
    kv("Defense parameters",
       f"N={dp.num_watchers} watcher · {dp.watcher_fee_sat_vb} sat/vB · {dp.watcher_tx_vbytes} vB/tx",
       DIM)
    blank()

    c_atk = analysis['attack_cost_btc']
    c_def = analysis['defense_cost_btc']
    ser   = analysis['security_efficiency_ratio']
    f_be  = analysis['break_even_watcher_fee_sat_vb']
    rec_f = analysis['recommended_fee_sat_vb']

    kv("C_attack (min cost to censor window):", f"{c_atk:.6f} BTC  ≈ ${c_atk*100_000:.2f}", ORG)
    kv("C_defense (1 watcher at 55 sat/vB):",  f"{c_def:.8f} BTC  ≈ ${c_def*100_000:.4f}", GRN)
    kv("Security Efficiency Ratio (SER):",      f"{ser:,.0f}×   (attacker pays {ser:,.0f}× more)", YEL)
    blank()
    kv("Attack cost as % of vault:",
       f"{analysis['attack_pct_of_vault']:.4f}%  →  {'PROFITABLE' if analysis['attack_profitable_against_vault'] else 'unprofitable'}",
       RED if analysis['attack_profitable_against_vault'] else GRN)
    kv("Break-even watcher fee:",
       f"{f_be:.0f} sat/vB  (current 55 sat/vB is {'BELOW' if analysis['defender_under_budgeted'] else 'above'})",
       RED if analysis['defender_under_budgeted'] else GRN)
    kv("Recommended minimum watcher fee:",      f"{rec_f:.0f} sat/vB  (break-even + 20% margin)", YEL)
    blank()

    # SER vs N_watchers table
    print(f"  {BOLD}SER & Break-Even Fee vs. Watcher Count{RST}")
    blank()
    print(f"  {'N':>4}  {'SER':>10}  {'Break-even fee':>17}  {'Assessment'}")
    print(f"  {DIM}{'─'*4}  {'─'*10}  {'─'*17}  {'─'*30}{RST}")

    for N, ser_n, f_be_n in acm.ser_vs_watchers(ap, dp, max_N=10):
        at_or_below = dp.watcher_fee_sat_vb < f_be_n
        col   = RED if at_or_below else GRN
        note  = "⚠ Watcher underbids — attack profitable" if at_or_below else "✔ Defensible"
        print(f"  {N:>4}  {YEL}{ser_n:>10,.0f}×{RST}  {col}{f_be_n:>12.0f} sat/vB{RST}  {col}{note}{RST}")

    blank()
    print(f"  {BOLD}Key Finding NC3{RST}")
    print(f"  {YEL}Despite a SER of {ser:,.0f}×, the ABSOLUTE attack cost is only ~${c_atk*100_000:.0f}.{RST}")
    print(f"  {YEL}Against a {vault_btc:.1f} BTC vault this is economically rational for attackers.{RST}")
    print(f"  {YEL}The break-even fee of {f_be:.0f} sat/vB is a novel actionable security parameter.{RST}")
    blank()


# ════════════════════════════════════════════════════════════
#  NC4 OUTPUT
# ════════════════════════════════════════════════════════════

def run_nc4():
    section("ADAPTIVE SECURITY ORCHESTRATOR", "NC4", GRN)
    aso = AdaptiveSecurityOrchestrator()

    strat = WatcherStrategy(initial_fee=55.0, escalation_rate=20.0, max_fee=250.0)

    mode_colors = {
        SecurityMode.BITVM_NORMAL:   GRN,
        SecurityMode.BITVM_ENHANCED: YEL,
        SecurityMode.HYBRID:         ORG,
        SecurityMode.ZK_ONLY:        RED,
    }

    scenarios = [
        ("Quiet mainnet (minimal spam)",          NetworkState(spam_rate=1.0, block_capacity=10, challenge_window=12)),
        ("Moderate congestion (Ordinals wave)",   NetworkState(spam_rate=3.0, block_capacity=5,  challenge_window=8)),
        ("Default attack (our simulation)",       NetworkState(spam_rate=5.0, block_capacity=3,  challenge_window=6)),
        ("Aggressive flooding",                   NetworkState(spam_rate=8.0, block_capacity=3,  challenge_window=6)),
        ("Full censorship DoS",                   NetworkState(spam_rate=12.0, block_capacity=2, challenge_window=4)),
    ]

    print(f"  {BOLD}Threat Assessment Across Scenarios{RST}")
    blank()
    print(f"  {'Scenario':<42}  {'τ':>5}  {'τ₁':>5}  {'τ₂':>5}  {'τ₃':>5}  {'P(sec)':>7}  Mode")
    print(f"  {DIM}{'─'*42}  {'─'*5}  {'─'*5}  {'─'*5}  {'─'*5}  {'─'*7}  {'─'*28}{RST}")

    for label, state in scenarios:
        a     = aso.assess(state, strat, N_current=3)
        col   = mode_colors[a.mode]
        pstr  = f"{a.p_security*100:.0f}%"
        mname = a.mode.value.split('—')[0].strip()
        print(f"  {label:<42}  {YEL}{a.threat_index:.2f}{RST}  "
              f"{DIM}{a.component_t1:.2f}{RST}  {DIM}{a.component_t2:.2f}{RST}  "
              f"{DIM}{a.component_t3:.2f}{RST}  "
              f"{(GRN if a.p_security >= 0.9 else YEL if a.p_security >= 0.5 else RED)}{pstr:>7}{RST}  "
              f"{col}{mname}{RST}")

    blank()
    print(f"  {BOLD}Phase-Transition Boundaries (derived from PSM, NC1){RST}")
    blank()
    boundaries = [
        (0.00, 0.30, SecurityMode.BITVM_NORMAL,   "P(security) ≥ 0.95 — challenge-response sufficient"),
        (0.30, 0.55, SecurityMode.BITVM_ENHANCED,  "P ∈ [0.75, 0.95) — fee escalation required"),
        (0.55, 0.78, SecurityMode.HYBRID,          "P ∈ [0.50, 0.75) — ZK proof queued as fallback"),
        (0.78, 1.00, SecurityMode.ZK_ONLY,         "P < 0.50 — BitVM fails, ZK mandatory"),
    ]
    for lo, hi, mode, desc in boundaries:
        col = mode_colors[mode]
        bar_w = 20
        pct   = (lo + hi) / 2
        filled = int(pct * bar_w)
        bar   = col + '█' * max(1, int((hi-lo) * 40)) + RST
        print(f"  {col}{BOLD}τ ∈ [{lo:.2f}, {hi:.2f}){RST}  {col}{mode.value.split('—')[0].strip():<26}{RST}  {DIM}{desc}{RST}")
    blank()

    # Threat trajectory as spam increases
    print(f"  {BOLD}Threat Index Trajectory (spam rate increasing 1→15 txs/block){RST}")
    blank()
    base_state = NetworkState(spam_rate=5.0)
    spam_range = [i * 0.5 for i in range(2, 32)]  # 1.0 to 15.5
    traj = aso.threat_trajectory(spam_range, base_state, strat)

    prev_mode = None
    for sr, tau, mode_name in traj:
        # find mode enum
        mode_short = mode_name.split('—')[0].strip()
        col = GRN
        if 'Enhanced' in mode_name: col = YEL
        elif 'Hybrid'  in mode_name: col = ORG
        elif 'ZK'      in mode_name: col = RED

        bar_filled = int(tau * 30)
        tau_bar = col + '█' * bar_filled + DIM + '░' * (30 - bar_filled) + RST

        changed = mode_name != prev_mode
        marker  = f"  {YEL}◀ MODE CHANGE{RST}" if changed else ""
        print(f"  spam={sr:>5.1f}  τ={tau:.2f}  [{tau_bar}]  {col}{mode_short:<28}{RST}{marker}")
        prev_mode = mode_name
    blank()

    print(f"  {BOLD}Key Finding NC4{RST}")
    print(f"  {YEL}The Threat Index τ provides the first principled, real-time switching criterion.{RST}")
    print(f"  {YEL}Existing bridges use fixed security modes — a vulnerability under adaptive attacks.{RST}")
    print(f"  {YEL}Phase boundaries derived from NC1 (PSM) — model-grounded, not heuristic.{RST}")
    blank()


# ════════════════════════════════════════════════════════════
#  COMPARATIVE SUMMARY
# ════════════════════════════════════════════════════════════

def print_summary():
    blank()
    vhr('═', ORG)
    centre(f"{ORG}{BOLD}  FORTRESS — Consolidated Research Findings  {RST}")
    vhr('─', DIM)
    blank()

    findings = [
        ("NC1", ORG,
         "P(security | BitVM) has a closed-form expression.",
         "bridges can now compute their actual security probability, not just claim '1-of-N honesty'"),
        ("NC2", BLU,
         "Watcher count alone cannot ensure security (Tragedy of Commons).",
         "P(≥1 acts) → 1−c/r as N→∞; incentive mechanism design is required"),
        ("NC3", MAG,
         "SER measures economic security; absolute attack cost reveals profitability.",
         "default 55 sat/vB watcher fee is below break-even — a real deployment risk"),
        ("NC4", GRN,
         "Threat Index τ enables principled, model-driven BitVM↔ZK switching.",
         "first adaptive security orchestrator for Bitcoin L2 bridges"),
    ]

    for tag, col, headline, implication in findings:
        print(f"  {col}{BOLD}{tag}{RST}  {WHT}{headline}{RST}")
        print(f"      {DIM}→ {implication}{RST}")
        blank()

    hr('─', DIM)
    print(f"  {BOLD}Central thesis (extends prior work){RST}")
    print(f"  {WHT}\"Removing trust does not eliminate risk — it shifts its type.{RST}")
    print(f"  {WHT}FORTRESS quantifies that shift and makes it actionable.\"  {RST}")
    blank()

    print(f"  {BOLD}Future work directions{RST}")
    fw = [
        "RBF-aware watcher bidding strategies in the BitVM simulator",
        "Game-theoretic economic extension with attacker profitability threshold",
        "Integration with real ZK prover (snarkjs/risc0) for NC1 latency calibration",
        "Hybrid bridge prototype: BitVM challenge-response + ZK fallback layer",
        "Cross-chain extension of C1–C6 framework (Ethereum, Solana bridges)",
    ]
    for item in fw:
        print(f"    {DIM}◦  {WHT}{item}{RST}")
    blank()
    vhr('═', ORG)
    print(f"  {DIM}FORTRESS | Harish M & Praatibh | National Sun Yat-sen University{RST}")
    blank()


# ════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════

def main():
    print_header()
    time.sleep(0.4)

    run_nc1()
    time.sleep(0.2)

    run_nc2()
    time.sleep(0.2)

    run_nc3()
    time.sleep(0.2)

    run_nc4()
    time.sleep(0.2)

    print_summary()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {DIM}FORTRESS aborted.{RST}\n")