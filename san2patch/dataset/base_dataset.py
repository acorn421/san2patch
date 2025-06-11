# Dataset downloader for Automated Program Repair (APR) tasks

import glob
import json
import os
import re
from abc import abstractmethod
from pathlib import Path

from dotenv import load_dotenv

from san2patch.utils.cmd import BaseCommander
from san2patch.utils.enum import LanguageEnum


# Class must must named in CamelCase (e.g. Code-Change-Data -> CodeChangeDataDataset, BFP Small -> BFPSmallDataset)
class BaseDataset(BaseCommander):
    name = None
    language: LanguageEnum = LanguageEnum.C

    def __init__(
        self,
        download_dir: str | None = None,
        raw_dir: str | None = None,
        preprocessed_dir: str | None = None,
        final_dir: str | None = None,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)

        load_dotenv(override=True)

        self.download_dir = (
            download_dir
            or (Path(os.getenv("DATASET_DOWNLOAD_DIR")) / self.name).resolve()
        )
        self.extracted_dir = (
            raw_dir or (Path(os.getenv("DATASET_EXTRACTED_DIR")) / self.name).resolve()
        )
        self.preprocessed_dir = (
            preprocessed_dir
            or (Path(os.getenv("DATASET_PREPROCESSED_DIR")) / self.name).resolve()
        )
        self.final_dir = (
            final_dir or (Path(os.getenv("DATASET_FINAL_DIR")) / self.name).resolve()
        )

        if self.name is None or self.name == "":
            raise ValueError("Dataset name is not set")

        if self.download_dir is None:
            raise ValueError("Dataset download directory is not set")
        if self.extracted_dir is None:
            raise ValueError("Dataset raw directory is not set")
        if self.preprocessed_dir is None:
            raise ValueError("Dataset output directory is not set")

        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir)
        if not os.path.exists(self.extracted_dir):
            os.makedirs(self.extracted_dir)
        if not os.path.exists(self.preprocessed_dir):
            os.makedirs(self.preprocessed_dir)

    def get_skip(self, par_dir):
        skip_file = os.path.join(par_dir, "skip")
        if not os.path.exists(skip_file):
            return []

        with open(skip_file, "r") as f:
            lines = f.readlines()

        return [line.split("\t")[0] for line in lines]

    def write_skip(self, par_dir, id, reason):
        self.logger.warning(f"Skipping {id}: {reason}")

        with open(os.path.join(par_dir, "skip"), "a") as f:
            f.write(f"{id}\t{reason}\n")

    @abstractmethod
    def chk_download(self):
        """
        Check if the dataset is already downloaded
        """
        raise NotImplementedError

    @abstractmethod
    def download(self):
        """
        Download the dataset in archive format (e.g. .zip, .tar.gz, etc.)
        """
        raise NotImplementedError

    @staticmethod
    def get_only_san_output(full_txt):
        if not full_txt:
            return False

        if "\r\n" in full_txt:
            full_lines = full_txt.split("\r\n")
        else:
            full_lines = full_txt.split("\n")

        # Get the sanitizer output
        start_res = [r"runtime error:", r"ERROR: .+Sanitizer:"]
        end_res = [r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in.+", r"SUMMARY: .+Sanitizer:"]

        start_line = None
        end_line = None

        for idx, line in enumerate(full_lines):
            if start_line == None and any(
                [re.search(start_re, line) for start_re in start_res]
            ):
                start_line = idx
            elif any([re.search(end_re, line) for end_re in end_res]):
                end_line = idx + 1

        if start_line is None or end_line is None:
            return False

        return "\n".join(full_lines[start_line:end_line])

    def setup_directory(self, parent_dir):
        self.patch_dir = os.path.join(parent_dir, "patch")
        self.vuln_dir = os.path.join(parent_dir, "vuln")
        self.san_dir = os.path.join(parent_dir, "sanitizer")
        self.san_raw_dir = os.path.join(parent_dir, "sanitizer_raw")
        self.repo_dir = os.path.join(parent_dir, "repo")
        self.repo_copy_dir = os.path.join(parent_dir, "repo_copy")

        if not os.path.exists(self.patch_dir):
            os.makedirs(self.patch_dir)
        if not os.path.exists(self.vuln_dir):
            os.makedirs(self.vuln_dir)
        if not os.path.exists(self.san_dir):
            os.makedirs(self.san_dir)
        if not os.path.exists(self.san_raw_dir):
            os.makedirs(self.san_raw_dir)
        if not os.path.exists(self.repo_dir):
            os.makedirs(self.repo_dir)
        if not os.path.exists(self.repo_copy_dir):
            os.makedirs(self.repo_copy_dir)

    def extract(self):
        """
        Extract the downloaded dataset and save it to the raw directory
        """
        # Check if Dataset is downloaded
        if not self.chk_download():
            raise ValueError(
                f"Dataset {self.name} is not downloaded. Please run `download` first."
            )

        # Set up directories
        self.setup_directory(self.extracted_dir)

    def download_repo(self):
        """
        Download the repository

        Recommended to be used after aggregation
        """
        if self.vuln_dir is None:
            self.vuln_dir = os.path.join(self.preprocessed_dir, "vuln")

        for _, _, files in os.walk(self.vuln_dir):
            for file in files:
                if file.endswith(".json"):
                    self.logger.debug(f"Downloading repository for {file}")

                    with open(
                        os.path.join(self.vuln_dir, file), "r", errors="ignore"
                    ) as f:
                        vuln_data = json.load(f)

                    git_repo = [
                        x
                        for x in vuln_data["affected"][0]["ranges"]
                        if x["type"] == "GIT"
                    ]

                    if not git_repo:
                        self.write_skip(
                            self.download_dir,
                            vuln_data["id"],
                            "No git repository found",
                        )
                        return

                    repo_url = git_repo[0]["repo"]
                    repo_name = repo_url.split("/")[-1].split(".")[0]

                    repo_dir = os.path.join(self.repo_dir, repo_name)

                    if os.path.exists(repo_dir):
                        self.logger.debug(
                            f"Repository directory already exists: {repo_dir}"
                        )
                    else:
                        self.logger.debug(f"Cloning repository: {repo_url}")
                        self.run_cmd(
                            f"git clone {repo_url} {repo_name}", cwd=self.repo_dir
                        )

                    self.logger.debug(f"Repository for {file} is downloaded.")

    def extract_and_save_patch_commit_id(self):
        """
        Extract and save the patch commit id to the preprocessed directory

        Only utilized if you didn't save the selected patch id during dataset construction
        """
        vuln_dir = os.path.join(self.preprocessed_dir, "vuln")
        patch_dir = os.path.join(self.preprocessed_dir, "patch")

        for _, _, files in os.walk(vuln_dir):
            for file in files:
                if file.endswith(".json"):
                    self.logger.debug(f"Extracting patch commit id for {file}")

                    with open(os.path.join(vuln_dir, file), "r", errors="ignore") as f:
                        vuln_data = json.load(f)

                    patch_file_name = glob.glob(
                        os.path.join(patch_dir, f"{vuln_data['id']}*.diff")
                    )

                    patch_commit_id = patch_file_name[0].split("_")[-1].split(".")[0]

                    vuln_data["patch_commit_id"] = patch_commit_id

                    with open(os.path.join(vuln_dir, file), "w") as f:
                        json.dump(vuln_data, f)

                    self.logger.debug(f"Saving patch commit id for {file}")

    def preprocess(self):
        """
        Preprocess the raw dataset
        """
        self.setup_directory(self.preprocessed_dir)
