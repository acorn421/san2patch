import datetime
import os
import signal
import warnings
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import click
import psutil
from aim import Run
from art import text2art
from dotenv import load_dotenv
from langchain.callbacks import tracing_v2_enabled
from langsmith import tracing_context
from rich.progress import track

import san2patch.dataset.test as test_dataset
from san2patch.context import San2PatchLogger
from san2patch.dataset.test.final_dataset import FinalTestDataset
from san2patch.patching.llm.anthropic_llm_patcher import (
    Claude3HaikuPatcher,
    Claude3OpusPatcher,
    Claude35SonnetPatcher,
)
from san2patch.patching.llm.base_llm_patcher import BaseLLMPatcher

# from san2patch.patching.llm.google_llm_patcher import (
from san2patch.patching.llm.google_llm_patcher import (
    Gemini15FlashPatcher,
    Gemini15ProPatcher,
)
from san2patch.patching.llm.openai_llm_patcher import (
    GPT4ominiPatcher as OpenAIGPT4ominiPatcher,
)
from san2patch.patching.llm.openai_llm_patcher import GPT4oPatcher as OpenAIGPT4oPatcher
from san2patch.patching.llm.openai_llm_patcher import GPT35Patcher as OpenAIGPT35Patcher
from san2patch.patching.patcher import San2Patcher, TestEvalRetCode
from san2patch.utils.enum import (
    MODEL_LIST,
    SELECT_METHODS,
    TEMPERATURE_SETTING,
    VERSION_LIST,
    ExperimentStepEnum,
)

warnings.filterwarnings("ignore", category=UserWarning, module="pydantic")

vuln_id_list = {
    "vulnloc": "CVE-2017-14745,CVE-2017-15020,CVE-2017-15025,CVE-2017-6965,gnubug-19784,gnubug-25003,gnubug-25023,gnubug-26545,bugchrom-1404,CVE-2017-9992,CVE-2016-8691,CVE-2016-9557,CVE-2016-5844,CVE-2012-2806,CVE-2017-15232,CVE-2018-14498,CVE-2018-19664,CVE-2016-9264,CVE-2018-8806,CVE-2018-8964,bugzilla-2611,bugzilla-2633,CVE-2016-10092,CVE-2016-10094,CVE-2016-10272,CVE-2016-3186,CVE-2016-5314,CVE-2016-5321,CVE-2016-9273,CVE-2016-9532,CVE-2017-5225,CVE-2017-7595,CVE-2017-7599,CVE-2017-7600,CVE-2017-7601,CVE-2012-5134,CVE-2016-1838,CVE-2016-1839,CVE-2017-5969,CVE-2013-7437,CVE-2017-5974,CVE-2017-5975,CVE-2017-5976",
    "san2vuln": "CVE-2024-24146,CVE-2024-24148,NOFIX-2024-002,NOFIX-2024-003,NOFIX-2024-004,NOFIX-2024-005,NOFIX-2024-006,NOFIX-2024-007,NOFIX-2024-008,NOFIX-2024-009,NOFIX-2024-010,NOFIX-2024-001,CVE-2022-26981,CVE-2022-31783,GIT-2024-1530,GIT-2024-1531,GIT-2024-1532,GIT-2024-1533,GIT-2024-1534,GIT-2024-1535,GIT-2024-1536,GIT-2024-1537,GIT-2024-1539,OSV-2024-1206,OSV-2024-1210,OSV-2024-1230,OSV-2024-1244",
}

logger = San2PatchLogger("RUN PATCH").logger


def terminate_process_and_children(pid):
    """
    Terminates the process with the given PID and all its child processes.
    """
    try:
        # Get the parent process using the given PID
        parent = psutil.Process(pid)
        # Find all child processes recursively
        children = parent.children(recursive=True)
        # Terminate all child processes
        for child in children:
            os.kill(child.pid, signal.SIGTERM)
        # Terminate the parent process
        os.kill(pid, signal.SIGTERM)
    except psutil.NoSuchProcess:
        print("The process has already been terminated.")
    except Exception as e:
        print(f"An error occurred: {e}")


@click.group()
@click.argument("dataset_name", type=click.Choice(["Final"]), default="Final")
@click.pass_context
def cli(ctx, dataset_name):
    load_dotenv(override=True)

    ctx.ensure_object(dict)

    try:
        dataset_class = getattr(test_dataset, dataset_name + "TestDataset")
    except AttributeError:
        raise ValueError(f"Dataset {dataset_name} not found")

    # Create dataset instance
    dataset_instance = dataset_class()

    ctx.obj["dataset_instance"] = dataset_instance


def run_patch_one(
    vuln_id: str,
    LLMPatcher: BaseLLMPatcher,
    version: VERSION_LIST = "tot",
    experiment_name: str | None = None,
    retry_cnt: int = 1,
    max_retry_cnt: int = 0,
    docker_id: str | None = None,
    select_method: SELECT_METHODS = "sample",
    temperature_setting: TEMPERATURE_SETTING = "medium",
    raise_exception: bool = False,
    halt_on_success: bool = True,
):
    # Logger setting
    diff_dir = (
        Path(os.getenv("DATASET_TEST_DIR")) / f"gen_diff_{experiment_name}" / vuln_id
    ).resolve()
    if not os.path.exists(diff_dir):
        os.makedirs(diff_dir)

    dataset = FinalTestDataset()
    dataset.name = "final-test"
    dataset.__init__()
    dataset.setup_directory(dataset.final_dir, experiment_name)

    logger = San2PatchLogger().logger

    logger.info(f"Starting patching in test {dataset.name}...")
    logger.info(f"Graph version: {version}")

    logger.info(f"dataset.final_dir: {dataset.final_dir}")
    logger.info(f"vuln_id_start: {vuln_id}")

    stage_num = 0

    res_file = os.path.join(diff_dir, "res.txt")

    # Count directory that starts with "stage_" to resume from the last stage
    last_try_cnt = len([x for x in os.listdir(diff_dir) if x.startswith("stage_")])

    for i in range(last_try_cnt, last_try_cnt + retry_cnt):
        if max_retry_cnt != 0 and i >= max_retry_cnt:
            logger.error(f"Max retry count reached for vuln_id: {vuln_id}. exiting...")
            break

        # Set up aim run
        try:
            aim_run = Run(repo=os.getenv("AIM_SERVER_URL", "http://localhost:53800"))
            aim_run.set_artifacts_uri(os.getenv("AIM_ARTIFACTS_URI", "file://."))
        except Exception:
            logger.warning("Cannot connect to aim server. Turn off aim.")
            aim_run = dict()

        aim_run["experiment_name"] = experiment_name
        aim_run["vuln_id"] = vuln_id
        aim_run["model"] = LLMPatcher.__name__
        aim_run["retry_cnt"] = retry_cnt
        aim_run["try"] = i
        aim_run["stage"] = stage_num
        aim_run["step"] = ExperimentStepEnum.START.value
        aim_run["version"] = version

        # Set up patcher
        patcher = San2Patcher(
            vuln_id=vuln_id,
            data_dir=Path(os.getenv("DATASET_TEST_DIR")).resolve(),
            mode="test",
            LLMPatcher=LLMPatcher,
            version=version,
            aim_run=aim_run,
            experiment_name=experiment_name,
            docker_id=docker_id,
            select_method=select_method,
            temperature_setting=temperature_setting,
        )

        logger.info(
            f"Starting patching stage {stage_num} try {i} for vuln_id: {vuln_id}"
        )

        def _run_patch():
            try:
                res = patcher.make_diff(try_cnt=i, stage=stage_num)

                # Re-evaluate if the patch is already successful
                if TestEvalRetCode.SUCCESS.value in res.patch_success:
                    # ret_code, err_msg = patcher.test_eval_patch()
                    # ret_code = ret_code.value

                    ret_code = TestEvalRetCode.SUCCESS.value
                    err_msg = ""

                    # Find the first success index
                    success_idx = res.patch_success.index(TestEvalRetCode.SUCCESS.value)

                    # Get success diff file from dataset_dir
                    success_diff_file = os.path.join(
                        dataset.gen_diff_dir,
                        vuln_id,
                        f"stage_{stage_num}_{i}",
                        f"{vuln_id}_{success_idx}.diff",
                    )

                    success_graph_output = os.path.join(
                        dataset.gen_diff_dir,
                        vuln_id,
                        f"stage_{stage_num}_{i}",
                        f"{vuln_id}_graph_output.json",
                    )

                    # Copy the success diff file to the vuln directory
                    vuln_dir = os.path.join(dataset.gen_diff_dir, vuln_id)

                    dataset.run_cmd(
                        f"cp {success_diff_file} {vuln_dir}/{experiment_name}_{vuln_id}_success.diff"
                    )
                    dataset.run_cmd(
                        f"cp {success_graph_output} {vuln_dir}/{experiment_name}_{vuln_id}_success.artifact"
                    )

                elif TestEvalRetCode.FUNC_FAILED.value in res.patch_success:
                    ret_code = TestEvalRetCode.FUNC_FAILED.value
                    err_msg = ""
                else:
                    patch_success = res.patch_success
                    ret_code = max(patch_success, key=patch_success.count)
                    err_msg = ""

                if isinstance(aim_run, Run):
                    aim_run["time"] = aim_run.duration

                try:
                    aim_run["cost"] = float(
                        cb.client.read_run(cb.latest_run.id).total_cost
                    )
                    aim_run["langsmith_url"] = cb.get_run_url()
                except Exception:
                    aim_run["cost"] = None
                    aim_run["langsmith_url"] = None

                aim_run["result"] = ret_code
                aim_run["error"] = err_msg
                aim_run["patch_cnt"] = len([x for x in res.patch_success if x])
                aim_run["patch_success"] = res.patch_success

                with open(res_file, "a") as f:
                    try:
                        f.write(
                            f"try: {i}\tstage: {stage_num}\tcode: {ret_code}\trun: {cb.get_run_url()}\n"
                        )
                    except Exception:
                        f.write(f"try: {i}\tstage: {stage_num}\tcode: {ret_code}\n")

                logger.info(
                    f"Ending patching stage {stage_num} try {i} for vuln_id: {vuln_id}"
                )

                if ret_code == TestEvalRetCode.SUCCESS.value:
                    logger.success(f"Patch success for vuln_id: {vuln_id}")
                    if halt_on_success:
                        return True

            except Exception as e:
                if isinstance(aim_run, Run):
                    aim_run["time"] = aim_run.duration
                try:
                    aim_run["cost"] = float(
                        cb.client.read_run(cb.latest_run.id).total_cost
                    )
                    aim_run["langsmith_url"] = cb.get_run_url()
                except Exception:
                    aim_run["cost"] = None
                    aim_run["langsmith_url"] = None

                aim_run["result"] = TestEvalRetCode.EXCEPTION_RAISED.value
                aim_run["error"] = str(e)

                logger.error(f"Exception occurred: {e}. Retrying...")
                if raise_exception:
                    raise e

            return False

        if os.getenv("LANGSMITH_API_KEY", "") != "":
            with tracing_v2_enabled() as cb:
                logger.info("Langsmith Tracing enabled")
                res = _run_patch()
                if res:
                    break

        else:
            with tracing_context(enabled=False):
                logger.info("Langsmith Tracing disabled")
                cb = None
                res = _run_patch()
                if res:
                    break

    logger.info(f"vuln_id_end: {vuln_id}")


@cli.command()
@click.argument("NUM_WORKERS", type=int, default=4)
@click.option(
    "--experiment-name",
    type=str,
    default=None,
    help="Experiment name. If not provided, the experiment name will be automatically generated by the current date and time.",
)
@click.option("--retry-cnt", type=int, default=5, help="Number of retries")
@click.option(
    "--max-retry-cnt",
    type=int,
    default=0,
    help="Maximum number of retries for accumulative experiments. If 0, it will retry indefinitely until retry-cnt is reached",
)
@click.option(
    "--model",
    type=click.Choice(
        [
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-3.5",
            "claude-3.5-sonnet",
            "claude-3-haiku",
            "claude-3-opus",
            "gemini-1.5-pro",
            "gemini-1.5-flash",
        ]
    ),
    default="gpt-4o",
    help="Model name to run",
)
@click.option(
    "--version",
    type=click.Choice(
        [
            "tot",
            "no_context",
            "cot",
            "zeroshot",
            "no_comprehend",
            "no_howtofix",
        ]
    ),
    default="tot",
    help="Prompting version",
)
@click.option(
    "--docker-id",
    type=str,
    default=None,
    help="Docker ID to run. If not provided, the docker id will be automatically detected by the name of the container (san2patch-benchmark).",
)
@click.option(
    "--vuln-ids",
    type=str,
    help="Comma separated list of vuln_ids to run, or group of vuln_ids (san2vuln, vulnloc). If not provided, all vuln_ids will be run.",
)
@click.option(
    "--select-method",
    type=str,
    default="sample",
    help="Select method for ToT (sample, greedy)",
)
@click.option(
    "--temperature-setting",
    type=str,
    default="medium_high",
    help="Temperature setting",
)
@click.option(
    "--raise-exception", type=bool, is_flag=True, default=False, help="Raise exception"
)
@click.pass_context
def run_patch(
    ctx,
    num_workers: int,
    experiment_name: str | None,
    retry_cnt: int,
    max_retry_cnt: int,
    model: MODEL_LIST,
    version: VERSION_LIST,
    docker_id: str | None,
    vuln_ids: list[str] | None,
    select_method: SELECT_METHODS | None,
    temperature_setting: TEMPERATURE_SETTING | None,
    raise_exception: bool,
):
    if experiment_name is None:
        experiment_name = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    print(text2art("San2Patch"))

    print("############################################")
    print(text2art(experiment_name))
    print("############################################")

    if vuln_ids is not None:
        if vuln_ids == "san2vuln":
            vuln_ids = vuln_id_list["san2vuln"]
        elif vuln_ids == "vulnloc":
            vuln_ids = vuln_id_list["vulnloc"]

        vuln_ids = vuln_ids.split(",")

    dataset: FinalTestDataset = ctx.obj["dataset_instance"]

    dataset.name = "final-test"
    dataset.__init__()
    dataset.setup_directory(dataset.final_dir, experiment_name)

    logger.info(f"Starting patching in test {dataset.name}...")

    args = []

    skip_list = dataset.get_skip(dataset.gen_diff_dir)
    for _, _, files in track(
        os.walk(dataset.vuln_dir), description="Processing patching"
    ):
        for file in files:
            if file.endswith(".json"):
                vuln_id = file.split(".")[0]

                if vuln_id in skip_list:
                    logger.warning(f"Skipping {vuln_id} due to previous error")
                    continue

                if vuln_ids is not None and vuln_id not in vuln_ids:
                    continue

                filename = os.path.join(dataset.gen_diff_dir, vuln_id, "res.txt")
                if os.path.exists(filename):
                    with open(filename, "r") as f:
                        res = f.read()
                    if "success" in res:
                        logger.warning(
                            f"Skipping {vuln_id} because it was already successful"
                        )
                        continue

                args.append(file.split(".")[0])

    if model == "gpt-4o":
        model_class = OpenAIGPT4oPatcher
    elif model == "gpt-4o-mini":
        model_class = OpenAIGPT4ominiPatcher
    elif model == "gpt-3.5":
        model_class = OpenAIGPT35Patcher
    elif model == "claude-3-opus":
        model_class = Claude3OpusPatcher
    elif model == "claude-3.5-sonnet":
        model_class = Claude35SonnetPatcher
    elif model == "claude-3-haiku":
        model_class = Claude3HaikuPatcher
    elif model == "gemini-1.5-pro":
        model_class = Gemini15ProPatcher
    elif model == "gemini-1.5-flash":
        model_class = Gemini15FlashPatcher
    else:
        raise ValueError(f"Model {model} not found")

    if num_workers == 1:
        for arg in args:
            run_patch_one(
                arg,
                model_class,
                version,
                experiment_name,
                retry_cnt,
                max_retry_cnt,
                docker_id,
                select_method,
                temperature_setting,
                raise_exception,
            )
    else:
        try:
            with ProcessPoolExecutor(max_workers=num_workers) as executor:
                futures = [
                    executor.submit(
                        run_patch_one,
                        arg,
                        model_class,
                        version,
                        experiment_name,
                        retry_cnt,
                        max_retry_cnt,
                        docker_id,
                        select_method,
                        temperature_setting,
                        raise_exception,
                    )
                    for arg in args
                ]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Exception occurred: {e}")
                        if raise_exception:
                            raise e
        except KeyboardInterrupt:
            logger.error("Keyboard interrupt occurred. Exiting...")
            executor.shutdown(wait=False, cancel_futures=True)
            current_pid = os.getpid()
            terminate_process_and_children(current_pid)
            raise
        finally:
            logger.success("All patching completed. Shutting down executor...")
            executor.shutdown(wait=True)

    logger.info(f"Patching completed for {experiment_name}")


if __name__ == "__main__":
    cli()
