from pydantic import BaseModel


class ComplianceMappingResponse(BaseModel):
    id: int
    stride_category: str
    threat_subtype: str
    framework: str
    control_id: str
    control_name: str

    model_config = {"from_attributes": True}
