import glob
import os
import shutil
from pathlib import Path

# import ray
from dotenv import load_dotenv

from san2patch.dataset.base_dataset import BaseDataset
from san2patch.dataset.test.san2patch_dataset import San2PatchDataset
from san2patch.utils.enum import LanguageEnum


class FinalTestDataset(BaseDataset):
    name = "final-test"
    language = LanguageEnum.C

    def setup_directory(self, parent_dir, experiment_name: str | None = None):
        super().setup_directory(parent_dir)

        if experiment_name is not None:
            self.gen_diff_dir = os.path.join(parent_dir, f"gen_diff_{experiment_name}")
        else:
            self.gen_diff_dir = os.path.join(parent_dir, "gen_diff")

        if not os.path.exists(self.gen_diff_dir):
            os.makedirs(self.gen_diff_dir)

    def chk_download(self):
        raise ValueError(
            "This is FinalDataset after aggregation. It does not support download."
        )

    def download(self):
        raise ValueError(
            "This is FinalDataset after aggregation. It does not support download."
        )

    def extract(self):
        raise ValueError(
            "This is FinalDataset after aggregation. It does not support extract."
        )

    def preprocess(self):
        raise ValueError(
            "This is FinalDataset after aggregation. It does not support preprocess."
        )

    def download_repo(self):
        raise NotImplementedError(
            "This is FinalDataset after aggregation. It does not support download_repo."
        )

    def aggregate(self):
        load_dotenv(override=True)

        self.final_dir = (Path(os.getenv("DATASET_FINAL_DIR")) / self.name).resolve()

        self.setup_directory(self.final_dir)

        # ALL_DATASET_CLASSES = [VulnLocDataset, San2PatchDataset]
        ALL_DATASET_CLASSES = [San2PatchDataset]
        ALL_DATASET_INSTANCES: list[BaseDataset] = [
            dataset_class() for dataset_class in ALL_DATASET_CLASSES
        ]

        self.logger.info("Starting aggregation...")

        dataset_ids = set()

        for dataset in ALL_DATASET_INSTANCES:
            self.logger.info(f"Aggregating dataset: {dataset.name}")

            dataset.setup_directory(dataset.preprocessed_dir)

            for _, _, files in os.walk(dataset.vuln_dir):
                for file in files:
                    if file.endswith(".json"):
                        # ID-based deduplication
                        vuln_id = file.split(".")[0]

                        self.logger.info(f"Starting processing vuln_id: {vuln_id}")

                        if vuln_id in dataset_ids:
                            self.logger.warning(
                                f"Duplicate vuln_id found: {vuln_id}. Skipping..."
                            )
                            continue

                        dataset_ids.add(vuln_id)

                        # Copy vuln file
                        shutil.copyfile(
                            os.path.join(dataset.vuln_dir, f"{vuln_id}.json"),
                            os.path.join(self.vuln_dir, f"{vuln_id}.json"),
                        )
                        # Copy sanitizer file
                        shutil.copyfile(
                            os.path.join(dataset.san_dir, f"{vuln_id}.san"),
                            os.path.join(self.san_dir, f"{vuln_id}.san"),
                        )
                        # Copy patch file
                        try:
                            patch_file = glob.glob(
                                os.path.join(dataset.patch_dir, f"{vuln_id}.diff")
                            )[0].split("/")[-1]
                            shutil.copyfile(
                                os.path.join(dataset.patch_dir, patch_file),
                                os.path.join(self.patch_dir, patch_file),
                            )
                        except IndexError:
                            self.logger.warning(f"Patch file not found for {vuln_id}")

                        # Copy repo dir
                        repo_dir = glob.glob(
                            os.path.join(dataset.repo_dir, f"*_{vuln_id}")
                        )[0].split("/")[-1]
                        shutil.copytree(
                            os.path.join(dataset.repo_dir, repo_dir),
                            os.path.join(self.repo_dir, repo_dir),
                        )

                        self.logger.info(f"Finished processing vuln_id: {vuln_id}")

        self.logger.info("Finished aggregation.")
