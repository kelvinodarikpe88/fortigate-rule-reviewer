import os

os.environ.setdefault("SERVICE_NAME", "fortigate-rule-reviewer")
os.environ.setdefault("SERVICE_VERSION", "1.0.0")

from fastapi import FastAPI, HTTPException  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from . import llm  # noqa: E402
from .fortigate import review  # noqa: E402
from .runtime import configure_logging, install_runtime  # noqa: E402

MAX_CONFIG_CHARS = 2_000_000

configure_logging()
app = FastAPI(title="fortigate-rule-reviewer", version="1.0.0")
install_runtime(app)


class ReviewRequest(BaseModel):
    config: str = Field(min_length=16)
    use_model: bool = False


@app.post("/v1/review")
def run_review(request: ReviewRequest):
    if len(request.config) > MAX_CONFIG_CHARS:
        raise HTTPException(status_code=413, detail="config exceeds 2 MB")
    result = review(request.config)
    if result["summary"]["rules"] == 0:
        raise HTTPException(
            status_code=422,
            detail="no 'config firewall policy' block found in the submitted configuration",
        )

    rule_ids = {item["rule_id"] for item in result["findings"]}
    rule_ids |= {str(n) for n in range(1, result["summary"]["rules"] + 1)}
    provider = llm.provider_from_env() if request.use_model else None
    for finding in result["findings"]:
        request_note = llm.build_change_request(finding, rule_ids, provider)
        finding["change_request"] = request_note["text"]
        finding["change_request_source"] = request_note["source"]
        if request_note["rejected"]:
            finding["change_request_rejected"] = request_note["rejected"]
    return result
