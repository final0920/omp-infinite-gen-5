// Fixed F05 structural registry. References pin F03 original reviewed notes, not executable algorithms.
const freeze=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;};
export const METHOD_REGISTRY_VERSION='20261024-methods-1';
export const METHOD_SPECS=freeze([
  {
    "id": "known-result-readback",
    "version": "1.0.0",
    "title": "已知结果回读",
    "sourceRefs": [
      {
        "id": "f03-hex-rays",
        "sha256": "10c29afede43752f86ced207105c40854629f55b0500bb5fe55db852f6e5ce02"
      }
    ],
    "supportedArchitectures": [
      "architecture-independent-navigation"
    ],
    "supportedIRs": [
      "function-dossier-v1",
      "caller-statement-navigation"
    ],
    "requiredPredicates": [
      "reported-result"
    ],
    "excludedPredicates": [],
    "informativePredicates": [
      "static-observation"
    ],
    "missingEvidenceActions": [
      {
        "predicateId": "reported-result",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      },
      {
        "predicateId": "static-observation",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      }
    ],
    "experimentTemplateId": "review-evidence",
    "verifierId": "method-structure-v1",
    "budgetClass": "read-only-32KiB",
    "limitations": [
      "Applicability selects a bounded investigation step; it proves no algorithm, equivalence, VM identity or business result.",
      "No method or article text is executed.",
      "Similarity is navigation only; no probability or automatic execution."
    ]
  },
  {
    "id": "address-space-check",
    "version": "1.0.0",
    "title": "地址空间核对",
    "sourceRefs": [
      {
        "id": "f03-hex-rays",
        "sha256": "10c29afede43752f86ced207105c40854629f55b0500bb5fe55db852f6e5ce02"
      }
    ],
    "supportedArchitectures": [
      "architecture-independent-navigation"
    ],
    "supportedIRs": [
      "function-dossier-v1",
      "caller-statement-navigation"
    ],
    "requiredPredicates": [
      "static-observation"
    ],
    "excludedPredicates": [],
    "informativePredicates": [],
    "missingEvidenceActions": [
      {
        "predicateId": "static-observation",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      }
    ],
    "experimentTemplateId": "review-evidence",
    "verifierId": "method-structure-v1",
    "budgetClass": "read-only-32KiB",
    "limitations": [
      "Applicability selects a bounded investigation step; it proves no algorithm, equivalence, VM identity or business result.",
      "No method or article text is executed.",
      "Similarity is navigation only; no probability or automatic execution."
    ]
  },
  {
    "id": "truncated-source-completion",
    "version": "1.0.0",
    "title": "截断来源补全",
    "sourceRefs": [
      {
        "id": "f03-d810",
        "sha256": "1c168079e1465243bff3e37bbf836e9d242cb68cb4e17b4568a2ed45e4e2c0b4"
      }
    ],
    "supportedArchitectures": [
      "architecture-independent-navigation"
    ],
    "supportedIRs": [
      "function-dossier-v1",
      "caller-statement-navigation"
    ],
    "requiredPredicates": [
      "truncated-source"
    ],
    "excludedPredicates": [],
    "informativePredicates": [],
    "missingEvidenceActions": [
      {
        "predicateId": "truncated-source",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      }
    ],
    "experimentTemplateId": "refresh-static-source",
    "verifierId": "method-structure-v1",
    "budgetClass": "read-only-32KiB",
    "limitations": [
      "Applicability selects a bounded investigation step; it proves no algorithm, equivalence, VM identity or business result.",
      "No method or article text is executed.",
      "Similarity is navigation only; no probability or automatic execution."
    ]
  },
  {
    "id": "argument-prototype-check",
    "version": "1.0.0",
    "title": "实参原型核对",
    "sourceRefs": [
      {
        "id": "f03-hex-rays",
        "sha256": "10c29afede43752f86ced207105c40854629f55b0500bb5fe55db852f6e5ce02"
      }
    ],
    "supportedArchitectures": [
      "architecture-independent-navigation"
    ],
    "supportedIRs": [
      "function-dossier-v1",
      "caller-statement-navigation"
    ],
    "requiredPredicates": [
      "static-observation"
    ],
    "excludedPredicates": [],
    "informativePredicates": [
      "prototype-known"
    ],
    "missingEvidenceActions": [
      {
        "predicateId": "static-observation",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      },
      {
        "predicateId": "prototype-known",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      }
    ],
    "experimentTemplateId": "review-evidence",
    "verifierId": "method-structure-v1",
    "budgetClass": "read-only-32KiB",
    "limitations": [
      "Applicability selects a bounded investigation step; it proves no algorithm, equivalence, VM identity or business result.",
      "No method or article text is executed.",
      "Similarity is navigation only; no probability or automatic execution."
    ]
  },
  {
    "id": "callee-family-grouping",
    "version": "1.0.0",
    "title": "变换与 callee 家族分组",
    "sourceRefs": [
      {
        "id": "f03-quarkslab",
        "sha256": "8623079a74ef5d53519872205f1414ef54c279eafff7dd6ef555a22538fceabb"
      }
    ],
    "supportedArchitectures": [
      "architecture-independent-navigation"
    ],
    "supportedIRs": [
      "function-dossier-v1",
      "caller-statement-navigation"
    ],
    "requiredPredicates": [
      "multiple-callees"
    ],
    "excludedPredicates": [],
    "informativePredicates": [
      "instance-identity"
    ],
    "missingEvidenceActions": [
      {
        "predicateId": "multiple-callees",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      },
      {
        "predicateId": "instance-identity",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      }
    ],
    "experimentTemplateId": "compare-inputs",
    "verifierId": "method-structure-v1",
    "budgetClass": "read-only-32KiB",
    "limitations": [
      "Applicability selects a bounded investigation step; it proves no algorithm, equivalence, VM identity or business result.",
      "No method or article text is executed.",
      "Similarity is navigation only; no probability or automatic execution."
    ]
  },
  {
    "id": "vm-instance-separation",
    "version": "1.0.0",
    "title": "VM 实例分离观察",
    "sourceRefs": [
      {
        "id": "f03-vm-disassembly",
        "sha256": "5fbfbc1108f8f615072cbedd7b6d58d4a62af7dfad70eb1baa6005010bbcc46d"
      }
    ],
    "supportedArchitectures": [
      "architecture-independent-navigation"
    ],
    "supportedIRs": [
      "function-dossier-v1",
      "caller-statement-navigation"
    ],
    "requiredPredicates": [
      "multiple-callees"
    ],
    "excludedPredicates": [],
    "informativePredicates": [
      "instance-identity"
    ],
    "missingEvidenceActions": [
      {
        "predicateId": "multiple-callees",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      },
      {
        "predicateId": "instance-identity",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      }
    ],
    "experimentTemplateId": "compare-inputs",
    "verifierId": "method-structure-v1",
    "budgetClass": "read-only-32KiB",
    "limitations": [
      "Applicability selects a bounded investigation step; it proves no algorithm, equivalence, VM identity or business result.",
      "No method or article text is executed.",
      "Similarity is navigation only; no probability or automatic execution."
    ]
  },
  {
    "id": "pure-expression-simplification",
    "version": "1.0.0",
    "title": "纯表达式候选简化",
    "sourceRefs": [
      {
        "id": "f03-msynth",
        "sha256": "05c511b4045da9dbf7976123d813ad989851a37ca00a6d0851e02c5538482edb"
      },
      {
        "id": "f03-simba",
        "sha256": "f1d73dba6ddf6fc027b9f1a73ba7c74ccf0e0147e3ea21744ebd1825d55044ee"
      },
      {
        "id": "f03-syntia",
        "sha256": "07e72276676819b4b9411d10ddaf78b1941ef2d0f9f7409149aa3a99ec1fb44d"
      },
      {
        "id": "f03-xyntia",
        "sha256": "2a3e6daef471b12a6e9db59da9ced931775809d660c03029b3d9a905d3446b3e"
      }
    ],
    "supportedArchitectures": [
      "x86-32",
      "x86-64",
      "arm64"
    ],
    "supportedIRs": [
      "typed-bitvector-expression-v1"
    ],
    "requiredPredicates": [
      "architecture-supported",
      "typed-expression-ir",
      "pure-expression"
    ],
    "excludedPredicates": [
      "declared-conflict"
    ],
    "informativePredicates": [],
    "missingEvidenceActions": [
      {
        "predicateId": "architecture-supported",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      },
      {
        "predicateId": "typed-expression-ir",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      },
      {
        "predicateId": "pure-expression",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      }
    ],
    "experimentTemplateId": "review-evidence",
    "verifierId": "method-structure-v1",
    "budgetClass": "read-only-32KiB",
    "limitations": [
      "Applicability selects a bounded investigation step; it proves no algorithm, equivalence, VM identity or business result.",
      "No method or article text is executed.",
      "Similarity is navigation only; no probability or automatic execution."
    ]
  },
  {
    "id": "conflicting-evidence-review",
    "version": "1.0.0",
    "title": "冲突证据复核",
    "sourceRefs": [
      {
        "id": "f03-hex-rays",
        "sha256": "10c29afede43752f86ced207105c40854629f55b0500bb5fe55db852f6e5ce02"
      }
    ],
    "supportedArchitectures": [
      "architecture-independent-navigation"
    ],
    "supportedIRs": [
      "function-dossier-v1",
      "caller-statement-navigation"
    ],
    "requiredPredicates": [
      "declared-conflict"
    ],
    "excludedPredicates": [],
    "informativePredicates": [],
    "missingEvidenceActions": [
      {
        "predicateId": "declared-conflict",
        "action": "collect-or-review-current-bound-source",
        "execution": "explicit-existing-tools-only"
      }
    ],
    "experimentTemplateId": "review-evidence",
    "verifierId": "method-structure-v1",
    "budgetClass": "read-only-32KiB",
    "limitations": [
      "Applicability selects a bounded investigation step; it proves no algorithm, equivalence, VM identity or business result.",
      "No method or article text is executed.",
      "Similarity is navigation only; no probability or automatic execution."
    ]
  }
]);
