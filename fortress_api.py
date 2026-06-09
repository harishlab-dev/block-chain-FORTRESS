"""
FORTRESS — FastAPI Backend
Python is the sole computational brain. The HTML frontend delegates ALL math here.

Endpoints
─────────
POST /api/nc1/security          — ProbabilisticSecurityModel: P(sec), per-block probs, N*
POST /api/nc1/heatmap           — Security phase diagram (spam × watcher grid)
POST /api/nc1/curve             — P(security) vs N curve

POST /api/nc2/nash              — WatcherCommonsGame: Nash α*, aggregate P, tragedy limit
POST /api/nc2/curve             — Participation curve over N range
POST /api/nc2/incentive         — Min reward for target security

POST /api/nc3/ser               — AttackCostModel: SER, break-even fee, full analysis
POST /api/nc3/sweep             — SER vs watcher count table

POST /api/nc4/assess            — AdaptiveSecurityOrchestrator: τ, mode, recommendations
POST /api/nc4/trajectory        — Threat trajectory as spam increases

GET  /api/state                 — Shared session state (multi-user)
POST /api/state                 — Update shared session state
GET  /api/log                   — Session action log
POST /api/log                   — Append log entry
POST /api/users/heartbeat       — User presence heartbeat
GET  /api/events                — SSE stream for real-time push to all clients
"""

from __future__ import annotations
import asyncio
import json
import math
import time
import uuid
from collections import deque
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

# ── Import the FORTRESS brain ───────────────────────────────────────────────
from fortress_models import (
    NetworkState,
    WatcherStrategy,
    WatcherEconomics,
    AttackParams,
    DefenseParams,
    ProbabilisticSecurityModel,
    WatcherCommonsGame,
    AttackCostModel,
    AdaptiveSecurityOrchestrator,
    SecurityMode,
)

app = FastAPI(title="FORTRESS API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ════════════════════════════════════════════════════════════
#  SINGLETON MODEL INSTANCES  (instantiated once, re-used)
# ════════════════════════════════════════════════════════════

_psm  = ProbabilisticSecurityModel()
_wcg  = WatcherCommonsGame()
_acm  = AttackCostModel()
_aso  = AdaptiveSecurityOrchestrator()

# ════════════════════════════════════════════════════════════
#  SHARED SESSION STATE  (in-memory; replace with Redis for prod)
# ════════════════════════════════════════════════════════════

_DEFAULT_PARAMS: Dict[str, Any] = {
    # NC1 / PSM
    "block_capacity":  3,
    "spam_rate":       5.0,
    "spam_fee_min":    85.0,
    "spam_fee_max":    130.0,
    "challenge_window": 6,
    "initial_fee":     55.0,
    "escalation_rate": 20.0,
    "max_fee":         250.0,
    "n_watchers":      5,
    # NC2 / WCG
    "monitoring_cost_sats":  1_000,
    "challenge_tx_fee_sats": 2_000,
    "personal_reward_sats":  5_000,
    "vault_value_sats":      1_265_000_000,
    # NC3 / ACM
    "attack_spam_per_block":  10,
    "attack_spam_fee":        130.0,
    "attack_tx_vbytes":       140,
    "watcher_tx_vbytes":      150,
    "vault_value_btc":        12.65,
    # Attack simulation
    "attack_active":   False,
}

_session_params: Dict[str, Any] = dict(_DEFAULT_PARAMS)
_session_log: deque = deque(maxlen=100)
_session_users: Dict[str, Dict] = {}   # name → {role, color, ts}

# SSE subscriber queues
_sse_subscribers: List[asyncio.Queue] = []

async def _broadcast(event_type: str, payload: Any) -> None:
    """Push a message to all connected SSE clients."""
    msg = json.dumps({"type": event_type, "data": payload, "ts": time.time()})
    dead = []
    for q in _sse_subscribers:
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        _sse_subscribers.remove(q)


# ════════════════════════════════════════════════════════════
#  PYDANTIC REQUEST SCHEMAS
# ════════════════════════════════════════════════════════════

class NC1SecurityRequest(BaseModel):
    block_capacity:    int   = 3
    spam_rate:         float = 5.0
    spam_fee_min:      float = 85.0
    spam_fee_max:      float = 130.0
    challenge_window:  int   = 6
    initial_fee:       float = 55.0
    escalation_rate:   float = 20.0
    max_fee:           float = 250.0
    n_watchers:        int   = 5

class NC1HeatmapRequest(BaseModel):
    block_capacity:    int   = 3
    spam_fee_min:      float = 85.0
    spam_fee_max:      float = 130.0
    challenge_window:  int   = 6
    initial_fee:       float = 55.0
    escalation_rate:   float = 20.0
    max_fee:           float = 250.0
    spam_rates:        List[float] = Field(default_factory=lambda: [float(i) for i in range(1, 13)])
    watcher_counts:    List[int]   = Field(default_factory=lambda: list(range(1, 13)))

class NC2Request(BaseModel):
    n_watchers:              int   = 5
    monitoring_cost_sats:    float = 1000.0
    challenge_tx_fee_sats:   float = 2000.0
    personal_reward_sats:    float = 5000.0
    vault_value_sats:        float = 1_265_000_000.0
    max_n:                   int   = 25

class NC3Request(BaseModel):
    challenge_window:     int   = 6
    block_capacity:       int   = 3
    attack_spam_per_block:int   = 10
    attack_spam_fee:      float = 130.0
    attack_tx_vbytes:     int   = 140
    num_watchers:         int   = 1
    watcher_fee_sat_vb:   float = 55.0
    watcher_tx_vbytes:    int   = 150
    vault_value_btc:      float = 12.65
    max_n_sweep:          int   = 15

class NC4Request(BaseModel):
    block_capacity:    int   = 3
    spam_rate:         float = 5.0
    spam_fee_min:      float = 85.0
    spam_fee_max:      float = 130.0
    challenge_window:  int   = 6
    initial_fee:       float = 55.0
    escalation_rate:   float = 20.0
    max_fee:           float = 250.0
    n_watchers:        int   = 3
    spam_range_max:    float = 15.0
    spam_range_step:   float = 0.5

class LogEntry(BaseModel):
    user:   str
    role:   str
    color:  int
    action: str

class UserHeartbeat(BaseModel):
    name:  str
    role:  str
    color: int

class StateUpdate(BaseModel):
    params: Dict[str, Any]
    user:   str
    role:   str


# ════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════

def _make_network_state(r: NC1SecurityRequest | NC4Request) -> NetworkState:
    return NetworkState(
        block_capacity=r.block_capacity,
        spam_rate=r.spam_rate,
        spam_fee_min=r.spam_fee_min,
        spam_fee_max=r.spam_fee_max,
        challenge_window=r.challenge_window,
        base_fee=r.initial_fee,
    )

def _make_strategy(r: NC1SecurityRequest | NC4Request) -> WatcherStrategy:
    return WatcherStrategy(
        initial_fee=r.initial_fee,
        escalation_rate=r.escalation_rate,
        max_fee=r.max_fee,
    )

def _mode_meta(mode: SecurityMode) -> Dict[str, str]:
    META = {
        SecurityMode.BITVM_NORMAL:   {"label": "BITVM_NORMAL",   "color": "teal",  "icon": "✓"},
        SecurityMode.BITVM_ENHANCED: {"label": "BITVM_ENHANCED", "color": "amber", "icon": "⚡"},
        SecurityMode.HYBRID:         {"label": "HYBRID",         "color": "orange","icon": "⚠"},
        SecurityMode.ZK_ONLY:        {"label": "ZK_ONLY",        "color": "red",   "icon": "⛔"},
    }
    return META[mode]


# ════════════════════════════════════════════════════════════
#  NC1 ROUTES  — Probabilistic Security Model
# ════════════════════════════════════════════════════════════

@app.post("/api/nc1/security")
async def nc1_security(req: NC1SecurityRequest):
    """
    Full NC1 computation:
    - Single watcher success probability + per-block breakdown
    - System P(security) for N watchers
    - Minimum watchers N* for 95%, 99%, 99.9% targets
    - Strategy comparison (static / adaptive / premium)
    """
    state    = _make_network_state(req)
    strategy = _make_strategy(req)

    p_single, per_block = _psm.single_watcher_success(strategy, state)
    p_system = _psm.system_security([strategy] * req.n_watchers, state)
    n_star_95  = _psm.min_watchers_for_target(0.95,  strategy, state)
    n_star_99  = _psm.min_watchers_for_target(0.99,  strategy, state)
    n_star_999 = _psm.min_watchers_for_target(0.999, strategy, state)

    # Per-block inclusion probabilities broken out
    per_block_detail = [
        {
            "block": t,
            "fee": min(req.initial_fee + t * req.escalation_rate, req.max_fee),
            "p_inclusion": per_block[t] if t < len(per_block) else 0.0,
        }
        for t in range(req.challenge_window)
    ]

    # Strategy comparison matrix
    strategies_to_compare = [
        ("Static 55",       WatcherStrategy(55.0,  0.0,  200.0)),
        ("Adaptive 20/blk", WatcherStrategy(55.0,  20.0, 250.0)),
        ("Premium 135",     WatcherStrategy(135.0, 10.0, 300.0)),
        ("Current",         strategy),
    ]
    comparison = []
    for label, s in strategies_to_compare:
        p, pb = _psm.single_watcher_success(s, state)
        comparison.append({
            "label":    label,
            "p_single": round(p, 6),
            "n_star_99": _psm.min_watchers_for_target(0.99, s, state),
        })

    return {
        "p_single_watcher":  round(p_single, 6),
        "p_system":          round(p_system, 6),
        "per_block":         per_block_detail,
        "n_star": {
            "95pct":  n_star_95,
            "99pct":  n_star_99,
            "999pct": n_star_999,
        },
        "strategy_comparison": comparison,
        "params": {
            "n_watchers": req.n_watchers,
            "challenge_window": req.challenge_window,
            "spam_rate": req.spam_rate,
            "initial_fee": req.initial_fee,
            "escalation_rate": req.escalation_rate,
        }
    }


@app.post("/api/nc1/heatmap")
async def nc1_heatmap(req: NC1HeatmapRequest):
    """
    Full security phase diagram: grid[spam_rate][n_watchers] = P(security).
    Reveals the phase-transition boundary visually.
    """
    strategy = WatcherStrategy(
        initial_fee=req.initial_fee,
        escalation_rate=req.escalation_rate,
        max_fee=req.max_fee,
    )
    base_state = NetworkState(
        block_capacity=req.block_capacity,
        spam_fee_min=req.spam_fee_min,
        spam_fee_max=req.spam_fee_max,
        challenge_window=req.challenge_window,
    )

    grid = _psm.security_heatmap(req.spam_rates, req.watcher_counts, strategy, base_state)

    return {
        "spam_rates":     req.spam_rates,
        "watcher_counts": req.watcher_counts,
        "grid": [[round(float(v), 4) for v in row] for row in grid],
    }


@app.post("/api/nc1/curve")
async def nc1_curve(req: NC1SecurityRequest):
    """
    P(security) vs N watchers up to N=25. Used for the security curve chart.
    Returns both realistic (with censorship) and ideal curves.
    """
    strategy = _make_strategy(req)

    # Ideal (no censorship)
    state_ideal = NetworkState(
        block_capacity=req.block_capacity,
        spam_rate=0.0,  # no attack
        spam_fee_min=req.spam_fee_min,
        spam_fee_max=req.spam_fee_max,
        challenge_window=req.challenge_window,
    )

    # Realistic (with attack)
    state_attack = _make_network_state(req)

    curve_realistic = _psm.security_curve(25, strategy, state_attack)
    curve_ideal     = _psm.security_curve(25, strategy, state_ideal)

    return {
        "realistic": [{"n": n, "p": round(p, 6)} for n, p in curve_realistic],
        "ideal":     [{"n": n, "p": round(p, 6)} for n, p in curve_ideal],
        "current_n": req.n_watchers,
    }


# ════════════════════════════════════════════════════════════
#  NC2 ROUTES  — Watcher Commons Game
# ════════════════════════════════════════════════════════════

@app.post("/api/nc2/nash")
async def nc2_nash(req: NC2Request):
    """
    Nash equilibrium results for current N.
    Includes tragedy limit, tragedy index, optimal N*.
    """
    econ = WatcherEconomics(
        monitoring_cost_sats=req.monitoring_cost_sats,
        challenge_tx_fee_sats=req.challenge_tx_fee_sats,
        personal_reward_sats=req.personal_reward_sats,
        vault_value_sats=req.vault_value_sats,
    )

    p_nash       = _wcg.nash_probability(req.n_watchers, econ)
    p_effective  = _wcg.effective_participation(req.n_watchers, econ)
    tragedy_lim  = _wcg.commons_tragedy_limit(econ)
    tragedy_idx  = _wcg.tragedy_index(req.n_watchers, econ)
    opt_n, opt_p = _wcg.optimal_watcher_count(econ, target=0.99, max_N=200)
    min_r_99     = _wcg.min_reward_for_target(req.n_watchers, econ, target=0.99)

    c = econ.monitoring_cost_sats + econ.challenge_tx_fee_sats
    r = econ.personal_reward_sats

    return {
        "n_watchers":       req.n_watchers,
        "p_nash_individual": round(p_nash, 6),
        "p_effective":       round(p_effective, 6),
        "tragedy_limit":     round(tragedy_lim, 6),
        "tragedy_index":     round(tragedy_idx, 6),
        "optimal_n":         opt_n,
        "optimal_p":         round(opt_p, 6),
        "min_reward_for_99sats": round(min_r_99, 0),
        "cost_ratio":        round(c / max(r, 1), 6),
        "c_sats":            c,
        "r_sats":            r,
    }


@app.post("/api/nc2/curve")
async def nc2_curve(req: NC2Request):
    """
    Full participation curve: [(N, p_nash, p_effective)] for N=1..max_n.
    Proves the tragedy of the commons mathematically.
    """
    econ = WatcherEconomics(
        monitoring_cost_sats=req.monitoring_cost_sats,
        challenge_tx_fee_sats=req.challenge_tx_fee_sats,
        personal_reward_sats=req.personal_reward_sats,
        vault_value_sats=req.vault_value_sats,
    )

    curve = _wcg.participation_curve(req.max_n, econ)
    limit = _wcg.commons_tragedy_limit(econ)

    return {
        "curve": [
            {"n": n, "p_individual": round(pi, 6), "p_effective": round(pe, 6)}
            for n, pi, pe in curve
        ],
        "tragedy_limit": round(limit, 6),
    }


@app.post("/api/nc2/incentive")
async def nc2_incentive(req: NC2Request):
    """
    Sweep: what reward is needed at each N to achieve 95% / 99% participation?
    """
    econ_base = WatcherEconomics(
        monitoring_cost_sats=req.monitoring_cost_sats,
        challenge_tx_fee_sats=req.challenge_tx_fee_sats,
        personal_reward_sats=req.personal_reward_sats,
        vault_value_sats=req.vault_value_sats,
    )

    rows = []
    for N in range(1, req.max_n + 1):
        r99  = _wcg.min_reward_for_target(N, econ_base, target=0.99)
        r95  = _wcg.min_reward_for_target(N, econ_base, target=0.95)
        rows.append({
            "n": N,
            "min_reward_for_95_sats":  round(r95, 0),
            "min_reward_for_99_sats":  round(r99, 0),
            "current_reward_adequate": econ_base.personal_reward_sats >= r99,
        })
    return {"rows": rows}


# ════════════════════════════════════════════════════════════
#  NC3 ROUTES  — Attack Cost Threshold
# ════════════════════════════════════════════════════════════

@app.post("/api/nc3/ser")
async def nc3_ser(req: NC3Request):
    """
    Full SER analysis: attack cost, defense cost, break-even fee, diagnosis.
    """
    ap = AttackParams(
        challenge_window=req.challenge_window,
        block_capacity=req.block_capacity,
        spam_per_block=req.attack_spam_per_block,
        spam_fee_sat_vb=req.attack_spam_fee,
        spam_tx_vbytes=req.attack_tx_vbytes,
    )
    dp = DefenseParams(
        num_watchers=req.num_watchers,
        watcher_fee_sat_vb=req.watcher_fee_sat_vb,
        watcher_tx_vbytes=req.watcher_tx_vbytes,
    )

    analysis = _acm.full_analysis(req.vault_value_btc, ap, dp)
    attack_cost  = _acm.attack_cost_btc(ap)
    defense_cost = _acm.defense_cost_btc(dp)

    return {
        "attack_cost_btc":    round(attack_cost, 8),
        "defense_cost_btc":   round(defense_cost, 8),
        "ser":                round(analysis["security_efficiency_ratio"], 3),
        "attack_pct_of_vault": round(analysis["attack_pct_of_vault"], 4),
        "attack_profitable":  analysis["attack_profitable_against_vault"],
        "break_even_fee":     round(analysis["break_even_watcher_fee_sat_vb"], 2),
        "defender_under_budgeted": analysis["defender_under_budgeted"],
        "recommended_fee":    round(analysis["recommended_fee_sat_vb"], 2),
        "vault_value_btc":    req.vault_value_btc,
        "current_watcher_fee": req.watcher_fee_sat_vb,
        "components": {
            "attack_window_blocks": req.challenge_window,
            "attack_spam_per_block": req.attack_spam_per_block,
            "attack_fee_sat_vb": req.attack_spam_fee,
            "attack_tx_vbytes": req.attack_tx_vbytes,
            "defense_num_watchers": req.num_watchers,
            "defense_fee_sat_vb": req.watcher_fee_sat_vb,
            "defense_tx_vbytes": req.watcher_tx_vbytes,
        }
    }


@app.post("/api/nc3/sweep")
async def nc3_sweep(req: NC3Request):
    """
    SER and break-even fee for N=1..max_n_sweep watchers.
    Shows economic landscape as watcher count grows.
    """
    ap = AttackParams(
        challenge_window=req.challenge_window,
        block_capacity=req.block_capacity,
        spam_per_block=req.attack_spam_per_block,
        spam_fee_sat_vb=req.attack_spam_fee,
        spam_tx_vbytes=req.attack_tx_vbytes,
    )
    base_dp = DefenseParams(
        num_watchers=req.num_watchers,
        watcher_fee_sat_vb=req.watcher_fee_sat_vb,
        watcher_tx_vbytes=req.watcher_tx_vbytes,
    )

    rows = _acm.ser_vs_watchers(ap, base_dp, max_N=req.max_n_sweep)
    return {
        "sweep": [
            {
                "n": n,
                "ser": round(ser, 2),
                "break_even_fee": round(f_be, 2),
                "defensible": req.watcher_fee_sat_vb >= f_be,
            }
            for n, ser, f_be in rows
        ]
    }


# ════════════════════════════════════════════════════════════
#  NC4 ROUTES  — Adaptive Security Orchestrator
# ════════════════════════════════════════════════════════════

@app.post("/api/nc4/assess")
async def nc4_assess(req: NC4Request):
    """
    Full real-time threat assessment: τ components, mode, recommendations.
    """
    state    = _make_network_state(req)
    strategy = _make_strategy(req)
    assess   = _aso.assess(state, strategy, N_current=req.n_watchers)
    meta     = _mode_meta(assess.mode)

    return {
        "tau":          round(assess.threat_index, 4),
        "tau1":         round(assess.component_t1, 4),
        "tau2":         round(assess.component_t2, 4),
        "tau3":         round(assess.component_t3, 4),
        "p_security":   round(assess.p_security, 6),
        "mode":         meta["label"],
        "mode_color":   meta["color"],
        "mode_icon":    meta["icon"],
        "mode_full":    assess.mode.value,
        "reason":       assess.reason,
        "recommended_fee": round(assess.recommended_fee, 2),
        "min_watchers_99": assess.min_watchers_99,
        "thresholds": {
            "safe_below":     0.30,
            "enhanced_below": 0.55,
            "hybrid_below":   0.78,
            "zk_only_above":  0.78,
        },
        "params": {
            "spam_rate":       req.spam_rate,
            "block_capacity":  req.block_capacity,
            "challenge_window": req.challenge_window,
            "n_watchers":      req.n_watchers,
        }
    }


@app.post("/api/nc4/trajectory")
async def nc4_trajectory(req: NC4Request):
    """
    Threat trajectory as spam rate increases from 0 to spam_range_max.
    Shows mode-transition points.
    """
    state    = _make_network_state(req)
    strategy = _make_strategy(req)

    steps = int(req.spam_range_max / req.spam_range_step)
    spam_range = [round(i * req.spam_range_step, 2) for i in range(1, steps + 2)]

    raw = _aso.threat_trajectory(spam_range, state, strategy)

    points = []
    prev_mode = None
    for sr, tau, mode_name in raw:
        mode_enum = next(m for m in SecurityMode if m.value == mode_name)
        meta = _mode_meta(mode_enum)
        changed = mode_name != prev_mode
        points.append({
            "spam_rate":    sr,
            "tau":          round(tau, 4),
            "mode":         meta["label"],
            "mode_color":   meta["color"],
            "mode_icon":    meta["icon"],
            "mode_changed": changed,
        })
        prev_mode = mode_name

    return {"trajectory": points, "current_spam": req.spam_rate}


# ════════════════════════════════════════════════════════════
#  MULTI-USER SESSION ROUTES
# ════════════════════════════════════════════════════════════

@app.get("/api/state")
async def get_state():
    return {"params": _session_params}


@app.post("/api/state")
async def update_state(update: StateUpdate):
    global _session_params
    for k, v in update.params.items():
        if k in _session_params:
            _session_params[k] = v

    await _broadcast("state_changed", {
        "params": _session_params,
        "changed_by": update.user,
        "role": update.role,
    })
    return {"ok": True, "params": _session_params}


@app.post("/api/state/reset")
async def reset_state(body: dict = {}):
    global _session_params
    _session_params = dict(_DEFAULT_PARAMS)
    user = body.get("user", "system")
    await _broadcast("state_reset", {"params": _session_params, "by": user})
    return {"ok": True}


@app.get("/api/log")
async def get_log():
    return {"entries": list(_session_log)}


@app.post("/api/log")
async def add_log(entry: LogEntry):
    record = {
        "id":     str(uuid.uuid4())[:8],
        "ts":     time.strftime("%H:%M:%S"),
        "user":   entry.user,
        "role":   entry.role,
        "color":  entry.color,
        "action": entry.action,
    }
    _session_log.appendleft(record)
    await _broadcast("log_entry", record)
    return {"ok": True}


@app.post("/api/users/heartbeat")
async def heartbeat(hb: UserHeartbeat):
    _session_users[hb.name] = {"role": hb.role, "color": hb.color, "ts": time.time()}
    # Prune stale (>12 s)
    now = time.time()
    stale = [n for n, u in _session_users.items() if now - u["ts"] > 12]
    for n in stale:
        del _session_users[n]
    active = [{"name": k, **v} for k, v in _session_users.items()]
    return {"active_users": active}


@app.get("/api/users")
async def get_users():
    now = time.time()
    active = [
        {"name": k, **v}
        for k, v in _session_users.items()
        if now - v["ts"] < 12
    ]
    return {"active_users": active}


# ════════════════════════════════════════════════════════════
#  ATTACK SIMULATION PRESETS
# ════════════════════════════════════════════════════════════

ATTACK_PRESETS = {
    "mempool_flood": {
        "spam_rate": 12.0,
        "block_capacity": 2,
        "spam_fee_max": 200.0,
        "attack_spam_fee": 190.0,
        "attack_spam_per_block": 15,
        "attack_active": True,
        "label": "Mempool Flood Attack",
    },
    "fee_squeeze": {
        "spam_rate": 8.0,
        "initial_fee": 55.0,
        "spam_fee_min": 80.0,
        "spam_fee_max": 160.0,
        "attack_spam_fee": 155.0,
        "attack_active": True,
        "label": "Fee Squeeze Attack",
    },
    "window_tightening": {
        "challenge_window": 3,
        "spam_rate": 6.0,
        "attack_active": True,
        "label": "Challenge Window Tightening",
    },
    "full_censorship": {
        "spam_rate": 20.0,
        "block_capacity": 1,
        "spam_fee_min": 150.0,
        "spam_fee_max": 250.0,
        "attack_spam_fee": 240.0,
        "attack_spam_per_block": 25,
        "attack_active": True,
        "label": "Full Censorship DoS",
    },
}

@app.post("/api/attack/launch/{preset_id}")
async def launch_attack(preset_id: str, body: dict = {}):
    if preset_id not in ATTACK_PRESETS:
        return {"ok": False, "error": "Unknown preset"}
    preset = ATTACK_PRESETS[preset_id]
    for k, v in preset.items():
        if k != "label" and k in _session_params:
            _session_params[k] = v
    _session_params["attack_active"] = True
    user = body.get("user", "attacker")
    await _broadcast("attack_launched", {
        "preset": preset_id,
        "label": preset["label"],
        "params": _session_params,
        "by": user,
    })
    log = {"id": str(uuid.uuid4())[:8], "ts": time.strftime("%H:%M:%S"),
           "user": user, "role": "attacker", "color": 5,
           "action": f"⚔ Attack launched: {preset['label']}"}
    _session_log.appendleft(log)
    await _broadcast("log_entry", log)
    return {"ok": True, "preset": preset_id, "params": _session_params}


@app.post("/api/attack/end")
async def end_attack(body: dict = {}):
    _session_params["attack_active"] = False
    _session_params["spam_rate"]      = 5.0
    _session_params["block_capacity"] = 3
    _session_params["spam_fee_max"]   = 130.0
    _session_params["spam_fee_min"]   = 85.0
    _session_params["attack_spam_fee"]      = 130.0
    _session_params["attack_spam_per_block"] = 10
    user = body.get("user", "system")
    await _broadcast("attack_ended", {"params": _session_params, "by": user})
    log = {"id": str(uuid.uuid4())[:8], "ts": time.strftime("%H:%M:%S"),
           "user": user, "role": "researcher", "color": 2,
           "action": "✕ Attack withdrawn — network normalizing"}
    _session_log.appendleft(log)
    await _broadcast("log_entry", log)
    return {"ok": True}


# ════════════════════════════════════════════════════════════
#  SERVER-SENT EVENTS  — real-time multi-user push
# ════════════════════════════════════════════════════════════

@app.get("/api/events")
async def sse_stream(request: Request):
    """
    SSE endpoint. Each client gets its own queue.
    Messages pushed via _broadcast() by any state-changing action.
    """
    q: asyncio.Queue = asyncio.Queue(maxsize=50)
    _sse_subscribers.append(q)

    async def generator():
        # Send initial hello
        yield f"data: {json.dumps({'type': 'connected', 'ts': time.time()})}\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=20.0)
                    yield f"data: {msg}\n\n"
                except asyncio.TimeoutError:
                    yield f"data: {json.dumps({'type': 'ping', 'ts': time.time()})}\n\n"
        finally:
            if q in _sse_subscribers:
                _sse_subscribers.remove(q)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ════════════════════════════════════════════════════════════
#  HEALTH / COMPOSITE
# ════════════════════════════════════════════════════════════

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "2.0.0", "models": ["PSM", "WCG", "ACM", "ASO"]}


@app.post("/api/full_compute")
async def full_compute(req: NC4Request):
    """
    One-shot endpoint: computes ALL four NC contributions from a single parameter set.
    Used by the frontend on any slider change to refresh all panels at once.
    """
    state    = _make_network_state(req)
    strategy = _make_strategy(req)

    # NC1
    p_single, per_block_raw = _psm.single_watcher_success(strategy, state)
    p_system = _psm.system_security([strategy] * req.n_watchers, state)
    n_star_99 = _psm.min_watchers_for_target(0.99, strategy, state)
    sec_curve = _psm.security_curve(20, strategy, state)

    # NC2 — use default economics
    econ = WatcherEconomics()
    p_nash      = _wcg.nash_probability(req.n_watchers, econ)
    p_effective = _wcg.effective_participation(req.n_watchers, econ)
    tragedy_lim = _wcg.commons_tragedy_limit(econ)
    participation_curve_raw = _wcg.participation_curve(20, econ)

    # NC3
    ap = AttackParams(
        challenge_window=req.challenge_window,
        block_capacity=req.block_capacity,
        spam_per_block=_session_params.get("attack_spam_per_block", 10),
        spam_fee_sat_vb=_session_params.get("attack_spam_fee", 130.0),
        spam_tx_vbytes=_session_params.get("attack_tx_vbytes", 140),
    )
    dp = DefenseParams(
        num_watchers=req.n_watchers,
        watcher_fee_sat_vb=req.initial_fee,
        watcher_tx_vbytes=150,
    )
    vault_btc = _session_params.get("vault_value_btc", 12.65)
    ser_analysis = _acm.full_analysis(vault_btc, ap, dp)
    ser = ser_analysis["security_efficiency_ratio"]

    # NC4
    assess = _aso.assess(state, strategy, N_current=req.n_watchers)
    meta = _mode_meta(assess.mode)

    return {
        "nc1": {
            "p_single":   round(p_single, 6),
            "p_system":   round(p_system, 6),
            "n_star_99":  n_star_99,
            "per_block":  [round(float(v), 4) for v in per_block_raw],
            "sec_curve":  [{"n": n, "p": round(p, 6)} for n, p in sec_curve],
        },
        "nc2": {
            "p_nash_individual": round(p_nash, 6),
            "p_effective":       round(p_effective, 6),
            "tragedy_limit":     round(tragedy_lim, 6),
            "participation_curve": [
                {"n": n, "p_individual": round(pi, 6), "p_effective": round(pe, 6)}
                for n, pi, pe in participation_curve_raw
            ],
        },
        "nc3": {
            "attack_cost_btc":   round(_acm.attack_cost_btc(ap), 8),
            "defense_cost_btc":  round(_acm.defense_cost_btc(dp), 8),
            "ser":               round(ser, 3),
            "break_even_fee":    round(ser_analysis["break_even_watcher_fee_sat_vb"], 2),
            "attack_profitable": ser_analysis["attack_profitable_against_vault"],
            "defender_under_budgeted": ser_analysis["defender_under_budgeted"],
        },
        "nc4": {
            "tau":          round(assess.threat_index, 4),
            "tau1":         round(assess.component_t1, 4),
            "tau2":         round(assess.component_t2, 4),
            "tau3":         round(assess.component_t3, 4),
            "p_security":   round(assess.p_security, 6),
            "mode":         meta["label"],
            "mode_color":   meta["color"],
            "mode_icon":    meta["icon"],
            "reason":       assess.reason,
            "recommended_fee": round(assess.recommended_fee, 2),
            "min_watchers_99": assess.min_watchers_99,
        },
        "attack_active": _session_params.get("attack_active", False),
    }


if __name__ == "__main__":
    import uvicorn
    print("\n  ₿  FORTRESS API — Python Backend")
    print("  ─────────────────────────────────")
    print("  http://localhost:8000")
    print("  http://localhost:8000/docs  (Swagger UI)")
    print("  Open fortress_app.html in your browser\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")