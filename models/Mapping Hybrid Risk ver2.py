# Hybrid Risk Mapping (Likelihood × Impact) + Threat-informed testing
# -------------------------------------------------------------------
# This script:
# 1) Generates mock data for 100 rows with ALL variables used in the unified equation.
# 2) Computes Residual Likelihood, Impact (expanded), Raw Risk, and Final Risk Score.
# 3) Saves results into CSV files for analysis or visualization.

import numpy as np
import pandas as pd
from pathlib import Path

# ---------- Helpers ----------
def normalize_weights(w):
    """Normalize weights so they sum to 1."""
    w = np.asarray(w, dtype=float)
    s = w.sum()
    return w / s if s != 0 else np.ones_like(w) / len(w)

def clip(v, lo, hi):
    """Clamp values to [lo, hi]."""
    return np.minimum(np.maximum(v, lo), hi)

def bucket_1_to_5(x):
    """Map RawRisk 1..25 → FinalScore 1..5 buckets."""
    x = np.asarray(x)
    return np.where(x <= 5, 1,
           np.where(x <= 10, 2,
           np.where(x <= 15, 3,
           np.where(x <= 20, 4, 5))))

# ---------- Mock data ----------
rng = np.random.default_rng(7)
N = 100
V = 3  # vectors: direct, indirect_rag, agent_tool
vecs = ["direct", "indirect_rag", "agent_tool"]

# Likelihood-side (per vector)
TA  = rng.uniform(2.0, 5.0, size=(N, V))   # Threat-agent (1-5)
VUL = rng.uniform(2.0, 5.0, size=(N, V))   # Vulnerability (1-5)
ASR = rng.uniform(0.0, 0.9, size=(N, V))   # Attack success rate (0-1)
CE  = rng.uniform(0.0, 0.7, size=(N, V))   # Control effectiveness (0-1)
W_vec_raw = rng.uniform(0.2, 1.0, size=(N, V))  # exposure weights
W_vec = (W_vec_raw.T / W_vec_raw.sum(axis=1)).T

# Blend weights for TA/VUL/ASR
alpha, beta, gamma = normalize_weights([0.35, 0.35, 0.30])

# Impact-side: Target (U,M,T)
T_U = rng.uniform(2.0, 5.0, size=N)
T_M = rng.uniform(2.0, 5.0, size=N)
T_T = rng.uniform(2.0, 5.0, size=N)
v_U, v_M, v_T = normalize_weights([0.25, 0.5, 0.25])

# CIA (C,I,A)
C = rng.uniform(2.0, 5.0, size=N)
I = rng.uniform(2.0, 5.0, size=N)
A = rng.uniform(2.0, 5.0, size=N)
wC, wI, wA = normalize_weights([0.30, 0.50, 0.20])

# Complexity (DIR, ATT, MUL)
DIR = rng.uniform(1.5, 5.0, size=N)
ATT = rng.uniform(1.5, 5.0, size=N)
MUL = rng.uniform(1.5, 5.0, size=N)
wDIR, wATT, wMUL = normalize_weights([0.30, 0.30, 0.40])

# Social engineering (AUTH, URG, SCA, REC, LIK, SPF, CON, F/G)
AUTH = rng.uniform(1.5, 5.0, size=N)
URG  = rng.uniform(1.5, 5.0, size=N)
SCA  = rng.uniform(1.5, 5.0, size=N)
REC  = rng.uniform(1.5, 5.0, size=N)
LIK  = rng.uniform(1.5, 5.0, size=N)
SPF  = rng.uniform(1.5, 5.0, size=N)
CON  = rng.uniform(1.5, 5.0, size=N)
FG   = rng.uniform(1.5, 5.0, size=N)
w_AUTH, w_URG, w_SCA, w_REC, w_LIK, w_SPF, w_CON, w_FG = normalize_weights(
    [0.12, 0.14, 0.10, 0.10, 0.10, 0.14, 0.15, 0.15]
)

# Meta-weights for impact dimensions
lambda_T, lambda_CIA, lambda_CPLX, lambda_SE = normalize_weights([0.25, 0.45, 0.15, 0.15])

# ---------- Residual Likelihood ----------
ASR5 = 1 + 4 * ASR                             # Map ASR 0–1 → 1–5
L_components = alpha*TA + beta*VUL + gamma*ASR5
L_residual = (W_vec * (1 - CE) * L_components).sum(axis=1)
L_residual = clip(L_residual, 1, 5)

# ---------- Impact (expanded) ----------
target_term = v_U*T_U + v_M*T_M + v_T*T_T
cia_term    = wC*C + wI*I + wA*A
cplx_term   = wDIR*DIR + wATT*ATT + wMUL*MUL
se_term     = (w_AUTH*AUTH + w_URG*URG + w_SCA*SCA + w_REC*REC +
               w_LIK*LIK + w_SPF*SPF + w_CON*CON + w_FG*FG)
Impact = (lambda_T*target_term +
          lambda_CIA*cia_term +
          lambda_CPLX*cplx_term +
          lambda_SE*se_term)
Impact = clip(Impact, 1, 5)

# ---------- Risk & Final Score ----------
RawRisk = L_residual * Impact
FinalScore = bucket_1_to_5(RawRisk)

# ---------- Assemble DataFrame ----------
cols = {}
# Likelihood-side per vector
for j, vname in enumerate(vecs):
    cols[f"TA_{vname}"] = np.round(TA[:, j], 2)
    cols[f"VUL_{vname}"] = np.round(VUL[:, j], 2)
    cols[f"ASR_{vname}"] = np.round(ASR[:, j], 3)
    cols[f"CE_{vname}"] = np.round(CE[:, j], 3)
    cols[f"w_{vname}"] = np.round(W_vec[:, j], 3)

# Blend weights
cols["alpha_TA"] = np.full(N, round(alpha, 3))
cols["beta_VUL"] = np.full(N, round(beta, 3))
cols["gamma_ASR"] = np.full(N, round(gamma, 3))

# Target impacts + weights
cols.update({"T_U": np.round(T_U, 2), "T_M": np.round(T_M, 2), "T_T": np.round(T_T, 2),
             "v_U": np.full(N, round(v_U, 3)), "v_M": np.full(N, round(v_M, 3)), "v_T": np.full(N, round(v_T, 3))})

# CIA + weights
cols.update({"C": np.round(C, 2), "I": np.round(I, 2), "A": np.round(A, 2),
             "wC": np.full(N, round(wC, 3)), "wI": np.full(N, round(wI, 3)), "wA": np.full(N, round(wA, 3))})

# Complexity + weights
cols.update({"DIR": np.round(DIR, 2), "ATT": np.round(ATT, 2), "MUL": np.round(MUL, 2),
             "wDIR": np.full(N, round(wDIR, 3)), "wATT": np.full(N, round(wATT, 3)), "wMUL": np.full(N, round(wMUL, 3))})

# Social engineering + weights
cols.update({"AUTH": np.round(AUTH, 2), "URG": np.round(URG, 2), "SCA": np.round(SCA, 2),
             "REC": np.round(REC, 2), "LIK": np.round(LIK, 2), "SPF": np.round(SPF, 2),
             "CON": np.round(CON, 2), "F_G": np.round(FG, 2),
             "w_AUTH": np.full(N, round(w_AUTH, 3)), "w_URG": np.full(N, round(w_URG, 3)),
             "w_SCA": np.full(N, round(w_SCA, 3)), "w_REC": np.full(N, round(w_REC, 3)),
             "w_LIK": np.full(N, round(w_LIK, 3)), "w_SPF": np.full(N, round(w_SPF, 3)),
             "w_CON": np.full(N, round(w_CON, 3)), "w_F_G": np.full(N, round(w_FG, 3))})

# Meta-weights
cols.update({"lambda_T": np.full(N, round(lambda_T, 3)),
             "lambda_CIA": np.full(N, round(lambda_CIA, 3)),
             "lambda_CPLX": np.full(N, round(lambda_CPLX, 3)),
             "lambda_SE": np.full(N, round(lambda_SE, 3))})

# Outputs
cols.update({"ResidualLikelihood(1-5)": np.round(L_residual, 2),
             "Impact(1-5)": np.round(Impact, 2),
             "RawRisk(1-25)": np.round(RawRisk, 2),
             "FinalScore(1-5)": FinalScore.astype(int)})

df_full = pd.DataFrame(cols)

# Save CSV
out_path = Path("risk_mapping_full_inputs_100.csv")
df_full.to_csv(out_path, index=False)

print(df_full.head(10))
