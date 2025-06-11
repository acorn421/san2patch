from pydantic import BaseModel, Field, model_validator

from san2patch.context import San2PatchContextManager
from san2patch.patching.prompt.base_prompts import BaseBranchPrompt, BasePrompt


#################################################################
######################## Model Classes ##########################
#################################################################
#! Comprehend
class RootCauseModel(BaseModel):
    vuln_root_cause: str = Field(
        description="The root cause of the vulnerability in CWE format. (CWE ID and Name)"
    )
    rationale: str = Field(
        description="Rationale why you think this is the root cause."
    )


class VulnTypeModel(BaseModel):
    vuln_type: str = Field(
        description="Type of vulnerability in CWE format (CWE ID and Name)."
    )
    rationale: str = Field(
        description="Rationale why you think this is the type of vulnerability."
    )


class VulnDescModel(BaseModel):
    vuln_description: str = Field(description="Description of the vulnerability.")
    rationale: str = Field(description="Rationale that supports the description.")


class ComprehendAggregateModel(BaseModel):
    vuln_root_cause: str = Field(
        description="The root cause of the vulnerability CWE format. (CWE ID and Name)"
    )
    vuln_type: str = Field(
        description="Type of vulnerability in CWE format. (CWE ID and Name)"
    )
    vuln_rationale: str = Field(
        description="Underlying rationales why vulnerabilities occur."
    )
    vuln_comprehension: str = Field(
        description="Detailed description of the vulnerability you understand."
    )


#! How To Fix
class FixGuidelineModel(BaseModel):
    fix_guideline: str = Field(
        description="General guideline to fix the vulnerability based on the type of vulnerability(CWE)"
    )
    fix_rationale: str = Field(description="Rationale how to fix the vulnerability.")


class FixExampleModel(BaseModel):
    fix_example: str = Field(
        description="Example of the fix for a vulnerability based on fix guideline."
    )
    fix_rationale: str = Field(description="Rationale how to fix the vulnerability.")


class FixDescriptionModel(BaseModel):
    fix_description: str = Field(
        description="Detailed description of the fix for the target vulnerability."
    )
    fix_rationale: str = Field(description="Rationale how to fix the vulnerability.")


class FixStrategyModel(BaseModel):
    fix_guideline: str = Field(
        description="General guideline to fix the vulnerability based on the type of vulnerability (CWE)"
    )
    fix_description: str = Field(
        description="Detailed description of the fix for the target vulnerability."
    )
    fix_rationale: str = Field(
        description="Rationale why the fix is applied to resolve the error."
    )


#! Where To Fix
class StackTraceModel(BaseModel):
    crash_stack_trace: list[str] = Field(
        description="The stack trace of the execution that directly caused the crash. The format should be {file_name}@{line_number}@{function_name}"
    )
    memory_free_stack_trace: list[str] = Field(
        description="Memory free stack trace of the vulnerability in Sanitizer output. The format should be {file_name}@{line_number}@{function_name}. If unknown, leave blank."
    )
    memory_allocate_stack_trace: list[str] = Field(
        description="Memory allocate stack trace of the vulnerability in Sanitizer output. The format should be {file_name}@{line_number}@{function_name}. If unknown, leave blank."
    )


class SelectLocationModel(BaseModel):
    fix_file_name: str = Field(
        ...,
        description="Name (and path, if needed) of the file to be fixed. Example: 'src/main.c'. [REQUIRED].",
    )
    fix_line: int = Field(
        ...,
        description="The primary line number where the fix applies (the core issue or key point to fix). [REQUIRED].",
    )
    fix_start_line: int = Field(
        ...,
        description="The first line number (inclusive) indicating where the code changes should begin. [REQUIRED].",
    )
    fix_end_line: int = Field(
        ...,
        description="The last line number (inclusive) indicating where the code changes should end. [REQUIRED].",
    )
    rationale: str = Field(
        ...,
        description="A concise explanation of why this fix is necessary at the specified lines (e.g., the root cause or logic behind fixing these lines). [REQUIRED].",
    )

    @model_validator(mode="before")
    @classmethod
    def validate_lines(cls, values):
        values = {k: int(v) if isinstance(v, float) else v for k, v in values.items()}

        fix_line = values.get("fix_line", None)
        start_line = values.get("fix_start_line", None)
        end_line = values.get("fix_end_line", None)

        if start_line is None or end_line is None:
            if fix_line is not None:
                values["fix_start_line"] = fix_line
                values["fix_end_line"] = fix_line
            else:
                raise ValueError(
                    "Either fix_line or fix_start_line and fix_end_line should be provided."
                )
        return values

    def validate_self(self, check_code=False):
        if self.fix_file_name == "":
            raise ValueError("File name should not be empty.")
        if self.fix_start_line <= 0 or self.fix_end_line <= 0 or self.fix_line <= 0:
            raise ValueError("Line number should be greater than 0.")
        if check_code and not San2PatchContextManager().check_code_line(
            self.fix_file_name, self.fix_line
        ):
            raise ValueError(
                "The line number does not exist in the file or the file does not exist."
            )

    def fix_filename(self):
        try:
            self.fix_file_name = San2PatchContextManager.fix_file_name(
                self.fix_file_name
            )
        except Exception as e:
            raise ValueError(f"Error in fixing file name: {e}")


class FaultLocalModel(BaseModel):
    selected_stack_trace: list[str] = Field(
        ...,
        description="Selected stack trace to fix. The format should be {file_name}@{line_number}@{function_name} [REQUIRED]",
    )
    fix_locations: list[SelectLocationModel] = Field(
        ...,
        description="Code locations that need to be modified to patch the vulnerability. You can choose multiple locations. [REQUIRED]",
    )
    fix_location_rationale: str = Field(
        ..., description="Rationale why the fix is applied the the locations [REQUIRED]"
    )

    def validate_self(self, check_code=False):
        if len(self.fix_locations) == 0:
            raise ValueError(
                "At least one location should be selected to fix the vulnerability."
            )
        for loc in self.fix_locations:
            loc.validate_self(check_code)

    def fix_filename(self):
        for loc in self.fix_locations:
            try:
                loc.fix_file_name = San2PatchContextManager().fix_file_name(
                    loc.fix_file_name
                )
            except Exception as e:
                raise ValueError(f"Error in getting file name: {e}")


class FixedFileNameModel(BaseModel):
    corrected_file_name: str = Field(..., description="The corrected file name.")


#! RunPatch
class PatchCodeModel(BaseModel):
    patched_code: str = Field(
        description="Candidate of patched code with the vulnerability fixed."
    )


class FixErrorModel(BaseModel):
    fixed_patched_functions: list[str] = Field(
        description="Patch function codes with the error fixed."
    )
    fix_rationale: str = Field(
        description="Rationale why the fix is applied to resolve the error."
    )


class FixErrorOneModel(BaseModel):
    fixed_patched_function: str = Field(
        description="Patch function codes with the error fixed."
    )
    fix_rationale: str = Field(
        description="Rationale why the fix is applied to resolve the error."
    )


class BuildErrorModel(BaseModel):
    failed_rationale: str = Field(description="Rationale why the build failed.")
    failed_files: list[str] = Field(description="List of files that failed to build.")
    failed_locations: list[str] = Field(
        description="Location of the build failure in the code. Location should be identified with as much detail as possible, down to the line number. e.g. {file_name}@{line number}"
    )
    failed_error_messages: list[str] = Field(
        description="Error messages from the build."
    )
    failed_dependencies: list[str] = Field(
        description="List of dependencies that failed to build."
    )


class FunctionalErrorModel(BaseModel):
    failed_rationale: str = Field(
        description="Rationale why the functional test failed."
    )
    failed_testcases_name: list[str] = Field(
        description="List of name  of test cases that failed."
    )
    failed_test_filename: list[str] = Field(
        description="List of test files that failed."
    )
    failed_error_messages: list[str] = Field(
        description="Error messages from the functional test."
    )


class VulnerabilityErrorModel(BaseModel):
    failed_rationale: str = Field(
        description="Rationale why the vulnerability test failed."
    )
    failed_error_messages: list[str] = Field(
        description="Error messages from the vulnerability test."
    )
    vuln_stack_trace: str = Field(
        description="Stack trace(or Call trace) of the vulnerability in Sanitizer output. If unknown, leave blank."
    )


#! Zeroshot patching version
class ZeroshotFaultLocalModel(BaseModel):
    fix_locations: list[SelectLocationModel] = Field(
        description="Code locations that need to be modified to patch the vulnerability"
    )

    def validate_self(self, check_code=False):
        if len(self.fix_locations) == 0:
            raise ValueError(
                "At least one location should be selected to fix the vulnerability."
            )
        for loc in self.fix_locations:
            loc.validate_self(check_code)

    def fix_filename(self):
        for loc in self.fix_locations:
            try:
                loc.fix_file_name = San2PatchContextManager().fix_file_name(
                    loc.fix_file_name
                )
            except Exception as e:
                raise ValueError(f"Error in getting file name: {e}")


class ZeroshotPatchCodeModel(BaseModel):
    patched_code: str = Field(
        description="Candidate of patched code with the vulnerability fixed."
    )


#################################################################
####################### Prompt Classes ##########################
#################################################################
#! Comprehend


class GetStackTraceCompPrompt(BasePrompt[StackTraceModel]):
    def __init__(self, **kwargs):
        super().__init__(StackTraceModel, "comprehend/get_stack_trace.jinja2", **kwargs)


class FilterStackTraceCompPrompt(BasePrompt[StackTraceModel]):
    def __init__(self, **kwargs):
        super().__init__(
            StackTraceModel, "comprehend/filter_stack_trace.jinja2", **kwargs
        )


class WrongStackTracePrompt(BasePrompt[StackTraceModel]):
    def __init__(self, **kwargs):
        super().__init__(
            StackTraceModel, "comprehend/wrong_stack_trace.jinja2", **kwargs
        )


class RootCausePrompt(BasePrompt[RootCauseModel]):
    def __init__(self, **kwargs):
        super().__init__(RootCauseModel, "comprehend/root_cause.jinja2", **kwargs)


class VulnTypePrompt(BasePrompt[VulnTypeModel]):
    def __init__(self, **kwargs):
        super().__init__(VulnTypeModel, "comprehend/vuln_type.jinja2", **kwargs)


class VulnDescPrompt(BasePrompt[VulnDescModel]):
    def __init__(self, **kwargs):
        super().__init__(VulnDescModel, "comprehend/comprehend.jinja2", **kwargs)


class ComprehendAggregatePrompt(BasePrompt[ComprehendAggregateModel]):
    def __init__(self, **kwargs):
        super().__init__(
            ComprehendAggregateModel, "comprehend/comprehend_aggregate.jinja2", **kwargs
        )


#! How To Fix
class FixStrategyPrompt(BasePrompt[FixStrategyModel]):
    def __init__(self, **kwargs):
        super().__init__(FixStrategyModel, "howtofix/fix_strategy.jinja2", **kwargs)


class FixStrategyBranchPrompt(BaseBranchPrompt[FixStrategyModel]):
    def __init__(self, branch_num: int = 3, **kwargs):
        super().__init__(
            FixStrategyModel,
            "howtofix/fix_strategy.jinja2",
            branch_num=branch_num,
            **kwargs,
        )


#! Where To Fix
class SelectLocationPrompt(BasePrompt[FaultLocalModel]):
    def __init__(self, **kwargs):
        super().__init__(FaultLocalModel, "wheretofix/select_location.jinja2", **kwargs)


class SelectLocationNoComprehendPrompt(BasePrompt[FaultLocalModel]):
    def __init__(self, **kwargs):
        super().__init__(
            FaultLocalModel, "wheretofix/select_location_no_comprehend.jinja2", **kwargs
        )


class SelectLocationBranchPrompt(BaseBranchPrompt[FaultLocalModel]):
    def __init__(self, branch_num: int = 3, **kwargs):
        super().__init__(
            FaultLocalModel,
            "wheretofix/select_location.jinja2",
            branch_num=branch_num,
            **kwargs,
        )


#! RunPatch
class PatchCodePrompt(BasePrompt[PatchCodeModel]):
    def __init__(self, **kwargs):
        super().__init__(PatchCodeModel, "genpatch/genpatch_code.jinja2", **kwargs)


class PatchCodeBranchPrompt(BaseBranchPrompt[PatchCodeModel]):
    def __init__(self, branch_num: int = 3, **kwargs):
        super().__init__(
            PatchCodeModel,
            "genpatch/genpatch_code.jinja2",
            branch_num=branch_num,
            **kwargs,
        )


class FixBuildErrorPrompt(BasePrompt[FixErrorModel]):
    def __init__(self, **kwargs):
        super().__init__(FixErrorModel, "genpatch/fix_build_error.jinja2", **kwargs)


class FixBuildErrorOnePrompt(BasePrompt[FixErrorOneModel]):
    def __init__(self, **kwargs):
        super().__init__(FixErrorOneModel, "genpatch/fix_build_error.jinja2", **kwargs)


# ! Simple patching version
class ZeroshotSelectLocationPrompt(BasePrompt[ZeroshotFaultLocalModel]):
    def __init__(self, **kwargs):
        super().__init__(
            ZeroshotFaultLocalModel, "wheretofix/wheretofix_simple.jinja2", **kwargs
        )


class ZeroshotPatchCodePrompt(BasePrompt[ZeroshotPatchCodeModel]):
    def __init__(self, **kwargs):
        super().__init__(
            ZeroshotPatchCodeModel, "genpatch/genpatch_code_simple.jinja2", **kwargs
        )
