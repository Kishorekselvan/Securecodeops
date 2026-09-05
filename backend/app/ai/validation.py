import json
from typing import Dict, Any, Optional
from app.ai.provider import get_llm_provider
from app.ai.prompts import VALIDATION_SYSTEM_PROMPT
from app.analysis.learning_engine import learning_engine

class FindingValidator:
    def __init__(self):
        self.provider = get_llm_provider()

    async def validate_finding(self, finding: Dict[str, Any], surrounding_code: str = "") -> Dict[str, Any]:
        # 1. First consult Continuous Learning Knowledge Base (Paper Section II-B)
        learned_match = learning_engine.check_learned_patterns(finding)
        if learned_match:
            return {
                "ai_validation_status": learned_match.get("validation_status", "VALIDATED"),
                "ai_reasoning": learned_match.get("reasoning", "Calibrated by continuous learning knowledge base."),
                "ai_confidence": learned_match.get("confidence", 0.95),
                "ai_severity_adjustment": "LOW" if learned_match.get("validation_status") == "FALSE_POSITIVE" else None,
                "ai_attack_scenario": "Suppressed based on verified developer feedback." if learned_match.get("validation_status") == "FALSE_POSITIVE" else "Verified attack path reinforced by team knowledge base.",
                "ai_remediation": finding.get("ai_remediation") or "Refer to project coding standards."
            }

        user_prompt = f"""
Analyze this security finding:
Title: {finding.get('title')}
Category: {finding.get('category')}
Scanner: {finding.get('scanner')}
File: {finding.get('file_path')} (Line {finding.get('line_number')})
Severity: {finding.get('severity')}
Description: {finding.get('description')}
Evidence Snippet:
```
{finding.get('code_snippet', '')}
```

Surrounding Code Context:
```
{surrounding_code}
```

Determine if this finding is a true positive exploit or false positive, explain your reasoning, and suggest remediation.
"""
        result = await self.provider.generate_json(VALIDATION_SYSTEM_PROMPT, user_prompt)
        
        if not result or "validation_status" not in result:
            return {
                "ai_validation_status": "UNAVAILABLE",
                "ai_reasoning": "AI validation provider did not return a structured response; relying on deterministic scanner evidence.",
                "ai_confidence": None,
                "ai_severity_adjustment": None,
                "ai_attack_scenario": None,
                "ai_remediation": None
            }

        return {
            "ai_validation_status": result.get("validation_status", "VALIDATED"),
            "ai_reasoning": result.get("reasoning", "Validated based on static context analysis."),
            "ai_confidence": result.get("confidence", 0.90),
            "ai_severity_adjustment": result.get("severity_adjustment"),
            "ai_attack_scenario": result.get("attack_scenario"),
            "ai_remediation": result.get("remediation")
        }
