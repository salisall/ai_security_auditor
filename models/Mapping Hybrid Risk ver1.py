# Hybrid Risk Mapping for Prompt-Injection (mock demo with 100 rows)
# ---------------------------------------------------------------
# This script:
# 1) Creates mock inputs for 100 items (e.g., models/systems).
# 2) Computes the unified risk equation with weighting + controls.
# 3) Outputs Residual Likelihood (1-5), Impact (1-5), Raw Risk (1-25), Final Score (1-5).

import numpy as np
import pandas as pd

# ---------- Helpers ----------
def normalize_weights(w):
    """Normalize a list/array of weights so they sum to 1."""
    w = np.asarray(w, dtype=float)
    s = w.sum()
    return w / s if s != 0 else np.ones_like(w) / len(w)

def clip(v, lo, hi):
    """Clamp values to [lo, hi] so we stay on the intended scales."""
    return np.minimum(np.maximum(v, lo), hi)

def bucket_1_to_5(x):
    """Map 1..25 into 1..5 buckets: 1–5→1, 6–10→2, 11–15→3, 16–20→4, 21–25→5."""
    x = np.asarray(x)
    return np.where(x <= 5, 1,
           np.where(x <= 10, 2,
           np.where(x <= 15, 3,
           np.where(x <= 20, 4, 5))))

# ---------- Mock data ----------
rng = np.random.default_rng(42)
N = 100                         # number of rows (e.g., models/configurations)

# Attack vectors: direct, indirect/RAG, agent/tool
vec_names = ["direct", "indirect_rag", "agent_tool"]
V = len(vec_names)

# Per-vector inputs (1..5 except ASR, CE):
TA  = rng.uniform(2.0, 5.0, size=(N, V))   # threat-agent (skill/motive/opportunity/size) → summarized 1..5
VUL = rng.uniform(2.0, 5.0, size=(N, V))   # vulnerability (discovery/exploit/awareness/detection) → 1..5
ASR = rng.uniform(0.0, 0.8, size=(N, V))   # attack success rate (0..1), e.g., red-team success %
CE  = rng.uniform(0.0, 0.6, size=(N, V))   # control effectiveness per vector (0..1 fraction reduced)

# Exposure weights per vector (row-wise) -- sum to 1
W_vec_raw = rng.uniform(0.2, 1.0, size=(N, V))
W_vec = (W_vec_raw.T / W_vec_raw.sum(axis=1)).T

# Blend weights for TA/VUL/ASR (same for all rows here; change as needed)
alpha, beta, gamma = normalize_weights([0.35, 0.35, 0.30])

# ---------- Impact inputs ----------
# Target impacts (User, Model, Third-party) on 1..5 + weights
T_targets = rng.uniform(2.0, 5.0, size=(N, 3))  # columns: [User, Model, Third-party]
v_t = normalize_weights([0.25, 0.50, 0.25])     # e.g., model-centric systems

# CIA impacts (C, I, A) on 1..5 + weights (Integrity heavier for agents)
CIA = rng.uniform(2.0, 5.0, size=(N, 3))        # columns: [C, I, A]
w_cia = normalize_weights([0.30, 0.50, 0.20])

# Attack complexity (Direct, Attachment, Multi-step) on 1..5 + weights
CPLX = rng.uniform(1.5, 5.0, size=(N, 3))       # columns: [DIR, ATT, MUL]
w_cplx = normalize_weights([0.30, 0.30, 0.40])  # multi-step slightly heavier

# Social engineering (AUTH, URG, SCA, REC, LIK, SPF, CON, F/G) on 1..5 + weights
SE = rng.uniform(1.5, 5.0, size=(N, 8))
w_se = normalize_weights([0.12, 0.14, 0.10, 0.10, 0.10, 0.14, 0.15, 0.15])

# Meta-weights for combining Impact dimensions (sum to 1)
lambda_T, lambda_CIA, lambda_CPLX, lambda_SE = normalize_weights([0.25, 0.45, 0.15, 0.15])

# ---------- Likelihood side (Residual) ----------
# Map ASR(0..1) -- 1..5 as (1 + 4*ASR) to align with TA/VUL scales
ASR5 = 1 + 4 * ASR

# Per-vector likelihood component: α*TA + β*VUL + γ*ASR5
L_components = alpha*TA + beta*VUL + gamma*ASR5

# Residual Likelihood = Σ_i w_i * (1-CE_i) * L_i, clipped to 1..5
L_residual = (W_vec * (1 - CE) * L_components).sum(axis=1)
L_residual = clip(L_residual, 1, 5)

# ---------- Impact side ----------
# Target term = Σ_t v_t * T_t
target_term = (T_targets * v_t).sum(axis=1)

# CIA term = wC*C + wI*I + wA*A
cia_term = (CIA * w_cia).sum(axis=1)

# Complexity term = wDIR*DIR + wATT*ATT + wMUL*MUL
cplx_term = (CPLX * w_cplx).sum(axis=1)

# Social-engineering term = Σ_s w_s * SE_s
se_term = (SE * w_se).sum(axis=1)

# Final Impact (1..5), as λ-weighted combination of the four dimensions
Impact = (lambda_T * target_term
          + lambda_CIA * cia_term
          + lambda_CPLX * cplx_term
          + lambda_SE * se_term)
Impact = clip(Impact, 1, 5)

# ---------- Risk + Bucketing ----------
RawRisk = L_residual * Impact           # 1..25 conceptual scale
FinalScore = bucket_1_to_5(RawRisk)     # map to 1..5 buckets

# ---------- Results table ----------
df = pd.DataFrame({
    "ResidualLikelihood(1-5)": np.round(L_residual, 2),
    "Impact(1-5)": np.round(Impact, 2),
    "RawRisk(1-25)": np.round(RawRisk, 2),
    "FinalScore(1-5)": FinalScore.astype(int),
    # few useful inputs for auditing
    "w_direct": np.round(W_vec[:,0], 2),
    "w_indirect_rag": np.round(W_vec[:,1], 2),
    "w_agent_tool": np.round(W_vec[:,2], 2),
    "CE_avg": np.round(CE.mean(axis=1), 2),
    "ASR_avg": np.round(ASR.mean(axis=1), 2),
})

print(df.head(10))
# df.to_csv("risk_mapping_mock_results.csv", index=False)   # uncomment to save
