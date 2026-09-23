# NIST AI RMF 1.0 (AI 100-1) Control Mapping

SMAOS is designed to generate the empirical, runtime evidence required to satisfy the **NIST Artificial Intelligence Risk Management Framework 1.0 (AI RMF)**. 

While the framework is structured around four core functions—Govern, Map, Measure, and Manage—standard enterprise deployments often fail at the **Measure** and **Manage** stages because they lack the data infrastructure to benchmark runtime risk. SMAOS fills this gap.

### Control Mappings

| NIST AI RMF Subcategory | Requirement Summary | How SMAOS Provides Evidence |
| :--- | :--- | :--- |
| **GOVERN 1.1** | Legal and regulatory requirements involving AI are understood, managed, and documented. | By enforcing the `dispatched_unconfirmed` state on wire-faults, SMAOS generates the explicit incident classification dossiers required by EU DORA Article 17. |
| **MAP 2.1** | Impacts to systems, individuals, and organizations are mapped, including unanticipated or downstream contextual factors. | SMAOS captures the physical wire boundaries of agent actions. The `audit_trace.mermaid` artifact provides a concrete map of the actual execution environment and downstream impacts when transport fails. |
| **MEASURE 2.3** | AI system risks are identified, measured, and tracked over time. | The 8-scenario fault injection suite quantifies the exact "Overclaim Rate" of an agent harness, turning an unmeasurable systemic risk into a deterministic KPI. |
| **MANAGE 1.1** | AI risks are managed and treated using resources and capabilities effectively. | SMAOS provides a drop-in Java code patch (`ProofOrStopFilter.java`) to directly treat and mitigate the measured Overclaim Rate at the application layer. |
| **GOVERN 2.1** | Roles and responsibilities related to mapping, measuring, and managing AI risks are documented and clear. | Every SMAOS receipt enforces `awaiting_human_validation` via the `human_oversight` payload, explicitly gating automated risk resolution to a designated organizational role. |

*Disclaimer: SMAOS provides cryptographic evidence and verification layers to support AI RMF implementation. It does not constitute formal regulatory certification.*
